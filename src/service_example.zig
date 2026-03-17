const std = @import("std");
const sphtud = @import("sphtud");
const builtin = @import("builtin");
const dbus = @import("sphdbus");
const mpris = @import("mpris");
const service_def = @import("test_service");

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

    switch (request) {
        .@"/dev/sphaerophoria/TestService" => |path_req| switch (path_req) {
            .@"dev.sphaerophoria.TestService" => |interface_req| switch (interface_req) {
                .method => |method_req| switch (method_req) {
                    .Hello => |args| {
                        var buf: [4096]u8 = undefined;
                        const s = try std.fmt.bufPrint(&buf, "Hello {s}", .{args.Name.inner});

                        // FIXME: Return types should be typed
                        try connection.ret(
                            message.serial,
                            message.headers.sender.?.inner,
                            dbus.DbusString{ .inner = s },
                        );
                    },
                    .Goodbye => |args| {
                        var buf: [4096]u8 = undefined;
                        const s = try std.fmt.bufPrint(&buf, "Goodbye {s}", .{args.Name.inner});
                        // FIXME: Return types should be typed
                        try connection.ret(
                            message.serial,
                            message.headers.sender.?.inner,
                            dbus.DbusString{ .inner = s },
                        );
                    },
                    .CallMe => |_| {
                        try connection.ret(
                            message.serial,
                            message.headers.sender.?.inner,
                            dbus.DbusString{ .inner = "maybe" },
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
    var connection = try dbus.dbusConnection(reader.interface(), &writer.interface);
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

    const cp = buf_alloc.checkpoint();
    while (true) {
        buf_alloc.restore(cp);
        diagnostics.reset();

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
            error.EndOfStream, error.WriteFailed, error.ReadFailed => {
                std.log.info("IO failure, shutting down", .{});
                break;
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
    }

    std.debug.print("done\n", .{});
}
