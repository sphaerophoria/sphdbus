const std = @import("std");
const sphtud = @import("sphtud");
const builtin = @import("builtin");
const dbus = @import("sphdbus");
const mpris = @import("mpris");
const service_def = @import("test_service");

fn waitForResponse(connection: *dbus.DbusConnection, reader: *sphtud.io.Reader, handle: dbus.CallHandle, parse_options: dbus.ParseOptions) !void {
    while (true) {
        const res = connection.poll(parse_options) catch |e| {
            if (reader.isWouldBlock(e)) {
                try sphtud.io.nanosleep(.fromMilliseconds(10));
                continue;
            }

            return e;
        };
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
    var message_buf: [4096]u8 = undefined;
    var diagnostics = dbus.DbusErrorDiagnostics.init(&message_buf);
    const request = dbus.service.handleMessage(service_def, scratch, message, connection, .{ .diagnostics = &diagnostics }) catch |e| {
        std.log.err("{s}", .{diagnostics.message()});
        var stderr_buf: [4096]u8 = undefined;
        const stderr = std.debug.lockStderr(&stderr_buf);
        defer std.debug.unlockStderr();

        diagnostics.dumpPacket(&stderr.file_writer.interface) catch {};

        switch (e) {
            error.WriteFailed, error.InternalError => return .shutdown,
            error.InvalidRequest => return .none,
        }
    } orelse return .none;

    const body_buf = try scratch.alloc(u8, 512 * 1024);
    var body: dbus.BodySerializer = undefined;
    switch (request) {
        .@"/dev/sphaerophoria/TestService" => |path_req| switch (path_req) {
            .@"dev.sphaerophoria.TestService" => |interface_req| switch (interface_req) {
                .method => |method_req| switch (method_req) {
                    .Hello => |args| {
                        var buf: [4096]u8 = undefined;
                        const s = try std.fmt.bufPrint(&buf, "Hello {s}", .{args.Name.inner});
                        body.initPinned(body_buf, args.retSignature());

                        try body.addString(s);

                        // FIXME: Return types should be typed
                        try connection.ret(
                            message.serial,
                            message.headers.sender.?.inner,
                            &body,
                        );
                    },
                    .Goodbye => |args| {
                        var buf: [4096]u8 = undefined;
                        const s = try std.fmt.bufPrint(&buf, "Goodbye {s}", .{args.Name.inner});

                        body.initPinned(body_buf, args.retSignature());
                        try body.addString(s);
                        try connection.ret(
                            message.serial,
                            message.headers.sender.?.inner,
                            &body,
                        );
                    },
                    .CallMe => |p| {
                        body.initPinned(body_buf, p.retSignature());
                        try body.addString("maybe");
                        try connection.ret(
                            message.serial,
                            message.headers.sender.?.inner,
                            &body,
                        );
                    },
                    .GetStructure => |args| {
                        body.initPinned(body_buf, args.retSignature());
                        try body.startStruct();
                        try body.addI64(0xcafef00d);
                        try body.addDouble(1.234);
                        try body.addByte('d');
                        try body.endStruct();

                        std.debug.print("Returning with {d}\n", .{message.serial});
                        try connection.ret(
                            message.serial,
                            message.headers.sender.?.inner,
                            &body,
                        );
                    },
                    .GetUintArray => |args| {
                        body.initPinned(body_buf, args.retSignature());
                        try body.startArray();

                        for (0..100) |i| {
                            try body.startArrayElem();
                            try body.addU32(@intCast(i));
                        }

                        try body.endArray();

                        try connection.ret(
                            message.serial,
                            message.headers.sender.?.inner,
                            &body,
                        );
                    },
                    .GetNestedStructArray => |args| {
                        body.initPinned(body_buf, args.retSignature());
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

                        try connection.ret(
                            message.serial,
                            message.headers.sender.?.inner,
                            &body,
                        );
                    },
                    .GetStructArray => |args| {
                        body.initPinned(body_buf, args.retSignature());
                        try body.startArray();

                        for (0..100) |i| {
                            try body.startArrayElem();

                            try body.startStruct();
                            try body.addString("hello");
                            try body.addI64(@intCast(i));
                            try body.endStruct();
                        }

                        try body.endArray();

                        try connection.ret(
                            message.serial,
                            message.headers.sender.?.inner,
                            &body,
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

pub fn main(init: std.process.Init.Minimal) !void {
    var alloc_buf: [1 * 1024 * 1024]u8 = undefined;
    var buf_alloc = sphtud.alloc.BufAllocator.init(&alloc_buf);

    const alloc = buf_alloc.allocator();

    const bus_path = try dbus.sessionBusPath(init.environ);
    const system = sphtud.io.system;
    const socket = try sphtud.io.socket(system.AF.UNIX, system.SOCK.STREAM, 0);
    try sphtud.io.connectUnix(socket, try .init(bus_path));

    var reader = sphtud.io.Reader.init(socket, try alloc.alloc(u8, 4096));
    var writer = sphtud.io.Writer.init(socket, try alloc.alloc(u8, 4096));

    var diagnostics = dbus.DbusErrorDiagnostics.init(try alloc.alloc(u8, 4096));
    const parse_options = dbus.ParseOptions{
        .diagnostics = &diagnostics,
    };
    var connection = try dbus.DbusConnection.init(&reader.interface, &writer.interface);
    while (true) {
        const res = connection.poll(parse_options) catch |e| {
            if (reader.isWouldBlock(e)) {
                try sphtud.io.nanosleep(.fromMilliseconds(10));
                continue;
            }
            return e;
        };

        if (res == .initialized) break;
    }

    // FIXME: Registration of name maybe should be owned by sphdbus
    var request_name_buf: [256]u8 = undefined;
    var request_name_body: dbus.BodySerializer = undefined;
    request_name_body.initPinned(&request_name_buf, "su");
    try request_name_body.addString("dev.sphaerophoria.TestService");
    try request_name_body.addU32(0);

    const handle = try connection.call(
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "org.freedesktop.DBus",
        "RequestName",
        &request_name_body,
    );

    try waitForResponse(&connection, &reader, handle, parse_options);

    var chain_buf: [100]usize = undefined;
    var loop = try sphtud.io.Loop.init(&chain_buf);
    try loop.register(.{
        .handle = socket,
        .id = 1,
        .read = true,
        .write = false,
    });

    const timer = try sphtud.io.timerfd_create(.BOOTTIME);
    try sphtud.io.timerfd_settime(timer, .{ .rel = .fromSeconds(1) }, .fromSeconds(1));

    try loop.register(.{
        .handle = timer,
        .id = 2,
        .read = true,
        .write = false,
    });

    const cp = buf_alloc.checkpoint();
    outer: while (true) {
        buf_alloc.restore(cp);
        diagnostics.reset();

        const loop_res = try loop.poll(-1) orelse continue;

        switch (loop_res) {
            // dbus notification
            1 => {
                while (true) {
                    const res = connection.poll(parse_options) catch |e| switch (e) {
                        error.Unrecoverable => {
                            std.log.err("Unrecoverable error, shutting down", .{});
                            try dumpDiagnostics(diagnostics);
                            break :outer;
                        },
                        error.ParseError => {
                            try dumpDiagnostics(diagnostics);
                            break :outer;
                        },
                        error.EndOfStream, error.WriteFailed => {
                            std.log.info("IO failure, shutting down: {t}", .{e});
                            return e;
                        },
                        error.ReadFailed => {
                            if (reader.isWouldBlock(e)) break;
                            return e;
                        },
                    };

                    const params = switch (res) {
                        .call => |params| params,
                        else => continue,
                    };

                    switch (try writeResponse(buf_alloc.backAllocator(), params, &connection)) {
                        .shutdown => break :outer,
                        .none => {},
                    }
                }
            },
            2 => {
                var buf: [8]u8 = undefined;
                _ = try std.posix.read(timer, &buf);

                var signal_buf: [64]u8 = undefined;
                var signal_body: dbus.BodySerializer = undefined;
                signal_body.initPinned(&signal_buf, "s");
                try signal_body.addString("hi");

                try connection.signal(
                    "/dev/sphaerophoria/TestService",
                    "dev.sphaerophoria.TestService",
                    "Update",
                    &signal_body,
                );
            },
            else => {},
        }
    }

    std.debug.print("done\n", .{});
}
