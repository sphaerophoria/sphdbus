const std = @import("std");
const sphtud = @import("sphtud");
const builtin = @import("builtin");
const dbus = @import("sphdbus");
const mpris = @import("mpris");
const service_def = @import("test_service");

fn writeBuffer(data: []const u8, path: []const u8) !void {
    const f = try std.fs.cwd().createFile(path, .{});
    defer f.close();

    try f.writeAll(data);
}

fn waitForResponse(connection: *dbus.DbusConnection, handle: dbus.CallHandle, parse_options: dbus.ParseOptions) !void {
    while (true) {
        const res = try connection.poll(parse_options);
        const response = switch (res) {
            .response => |r| r,
            else => continue,
        };

        if (response.handle.inner == handle.inner) break;
    }
}

const ResponseAction = enum {
    none,
    shutdown,
};

fn writeResponse(scratch: std.mem.Allocator, message: dbus.ParsedMessage, connection: *dbus.DbusConnection) !ResponseAction {
    const request = dbus.service.handleMessage(service_def, scratch, message, connection) catch |e| switch (e) {
        error.WriteFailed, error.InternalError => return .shutdown,
        error.InvalidRequest => return .none,
    } orelse return .none;

    const body_buf = try scratch.alloc(u8, 512 * 1024);
    var body: dbus.BodySerializer = undefined;
    body.initPinned(body_buf);
    switch (request) {
        .@"/dev/sphaerophoria/TestService" => |path_req| switch (path_req) {
            .@"dev.sphaerophoria.TestService" => |interface_req| switch (interface_req) {
                .method => |method_req| switch (method_req) {
                    .Hello => |args| {
                        var buf: [4096]u8 = undefined;
                        const s = try std.fmt.bufPrint(&buf, "Hello {s}", .{args.Name.inner});

                        try body.addString(s);

                        // FIXME: Return types should be typed
                        try connection.ret2(
                            message.serial,
                            message.headers.sender.?.inner,
                            body,
                        );
                    },
                    .Goodbye => |args| {
                        var buf: [4096]u8 = undefined;
                        const s = try std.fmt.bufPrint(&buf, "Goodbye {s}", .{args.Name.inner});

                        try body.addString(s);
                        // FIXME: Return types should be typed
                        try connection.ret2(
                            message.serial,
                            message.headers.sender.?.inner,
                            body,
                        );
                    },
                    .CallMe => |_| {
                        try body.addString("maybe");
                        try connection.ret2(
                            message.serial,
                            message.headers.sender.?.inner,
                            body,
                        );
                    },
                    .GetStructure => |_| {
                        try body.startStruct();
                        try body.addI64(0xcafef00d);
                        try body.addDouble(1.234);
                        try body.addByte('d');
                        try body.endStruct();

                        try connection.ret2(
                            message.serial,
                            message.headers.sender.?.inner,
                            body,
                        );
                    },
                    .GetUintArray => |_| {
                        try body.startArray();

                        for (0..100) |i| {
                            try body.startArrayElem();
                            try body.addU32(@intCast(i));
                        }

                        try body.endArray();

                        try connection.ret2(
                            message.serial,
                            message.headers.sender.?.inner,
                            body,
                        );
                    },
                    .GetNestedStructArray => |_| {
                        try body.startArray();

                        for (0..2) |j| {
                            try body.startArrayElem();

                            try body.startArray();

                            for (0..100) |i| {
                                try body.startArrayElem();

                                try body.startStruct();
                                try body.addString("hello");
                                try body.addI64(@intCast(j * 100 + i));
                                try body.endStruct();

                            }

                            try body.endArray();
                        }
                        try body.endArray();

                        std.debug.print("{s}\n", .{body.type_string.items});
                        try connection.ret2(
                            message.serial,
                            message.headers.sender.?.inner,
                            body,
                        );
                    },
                    .GetStructArray => |_| {
                        try body.startArray();

                        for (0..100) |i| {
                            try body.startArrayElem();

                            try body.startStruct();
                            try body.addString("hello");
                            try body.addI64(@intCast(i));
                            try body.endStruct();
                        }

                        try body.endArray();
                        std.debug.print("{s}\n", .{body.type_string.items});

                        const PreviousStruct = struct {
                            s: dbus.DbusString,
                            x: i64,
                        };


                        var old_data: [100]PreviousStruct = undefined;
                        for (&old_data, 0..) |*v, i| {
                            v.s = .{ .inner = "hello" };
                            v.x = @intCast(i);
                        }

                        var old_version_buf: [512 * 1024]u8 = undefined;
                        var writer = std.Io.Writer.fixed(&old_version_buf);
                        try dbus.dbusSerialize(&writer, &old_data);

                        try writeBuffer(writer.buffered(), "old.bin");
                        try writeBuffer(body.writer.buffered(), "new.bin");

                        std.debug.assert(std.mem.eql(u8, writer.buffered(), body.writer.buffered()));

                        try connection.ret2(
                            message.serial,
                            message.headers.sender.?.inner,
                            body,
                        );
                    },
                },
                else => unreachable,
            },
        },
    }

    return .none;
}

fn dumpDiagnostics(diagnostics: dbus.DbusErrorDiagnostics) !void {
    const msg = diagnostics.message();
    if (msg.len > 0) {
        std.log.err("{s}", .{msg});
    }

    var buf: [8192]u8 = undefined;
    var bufw = std.Io.Writer.fixed(&buf);
    try diagnostics.dumpPacket(&bufw);

    const written = bufw.buffered();
    if (written.len > 0) {
        std.log.err("\n{s}", .{written});
    }
}

pub fn main() !void {
    var alloc_buf: [1 * 1024 * 1024]u8 = undefined;
    var buf_alloc = sphtud.alloc.BufAllocator.init(&alloc_buf);

    const alloc = buf_alloc.allocator();

    const stream = try dbus.sessionBus();

    const reader = try alloc.create(std.net.Stream.Reader);
    reader.* = stream.reader(try alloc.alloc(u8, 4096));

    const writer = try alloc.create(std.net.Stream.Writer);
    writer.* = stream.writer(try alloc.alloc(u8, 4096));

    var diagnostics = dbus.DbusErrorDiagnostics.init(try alloc.alloc(u8, 4096));
    const parse_options = dbus.ParseOptions{
        .diagnostics = &diagnostics,
    };
    var connection = try dbus.DbusConnection.init(reader.interface(), &writer.interface);
    while (try connection.poll(parse_options) != .initialized) {}

    // FIXME: Registration of name maybe should be owned by sphdbus
    const handle = try connection.call(
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "org.freedesktop.DBus",
        "RequestName",
        .{
            dbus.DbusString{ .inner = "dev.sphaerophoria.TestService" },
            @as(u32, 0),
        },
    );

    try waitForResponse(&connection, handle, parse_options);

    try sphtud.event.setNonblock(stream.handle);

    var loop = try sphtud.event.Loop2.init();
    try loop.register(.{
        .handle = stream.handle,
        .id = 1,
        .read = true,
        .write = false,
    });

    const timer = try std.posix.timerfd_create(.MONOTONIC, .{});
    const interval = std.posix.system.itimerspec{
        .it_value = .{
            .nsec = 0,
            .sec = 1,
        },
        .it_interval = .{
            .nsec = 0,
            .sec = 1,
        },
    };
    try sphtud.event.setNonblock(timer);

    try std.posix.timerfd_settime(timer, .{
        .ABSTIME = false,
        .CANCEL_ON_SET = false
    }, &interval, null);

    try loop.register(.{
        .handle = timer,
        .id = 2,
        .read = true,
        .write = false,
    });

    const cp = buf_alloc.checkpoint();
    while (true) {
        buf_alloc.restore(cp);
        diagnostics.reset();

        const loop_res = try loop.poll(-1) orelse continue;

        switch (loop_res) {
            // dbus notification
            1 => {
                const res = connection.poll(parse_options) catch |e| switch (e) {
                    error.Unrecoverable => {
                        std.log.err("Unrecoverable error, shutting down", .{});
                        try dumpDiagnostics(diagnostics);
                        break;
                    },
                    error.ParseError => {
                        try dumpDiagnostics(diagnostics);
                        break;
                    },
                    error.EndOfStream, error.WriteFailed => {
                        std.log.info("IO failure, shutting down: {t}", .{e});
                        return e;
                    },
                    error.ReadFailed => {
                        const source_err = reader.getError() orelse return e;
                        if (source_err == error.WouldBlock) {
                            continue;
                        }
                        return e;
                    },
                };

                const params = switch (res) {
                    .call => |params| params,
                    else => continue,
                };

                switch (try writeResponse(buf_alloc.backAllocator(), params, &connection)) {
                    .shutdown => break,
                    .none => {},
                }
            },
            2 => {
                var buf: [8]u8 = undefined;
                _ = try std.posix.read(timer, &buf);

                try connection.signal(
                    "/dev/sphaerophoria/TestService",
                    "dev.sphaerophoria.TestService",
                    "Update",
                    dbus.DbusString { .inner = "hi" },
                );
            },
            else => {},
        }


    }

    std.debug.print("done\n", .{});
}
