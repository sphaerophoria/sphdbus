const std = @import("std");
const sphtud = @import("sphtud");
const builtin = @import("builtin");
const dbus = @import("sphdbus");
const mpris = @import("mpris");

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

const service_object = "/dev/sphaerophoria/TestService";

const ExpectedObjectPath = enum {
    @"/",
    @"/dev",
    @"/dev/sphaerophoria",
    @"/dev/sphaerophoria/TestService",

    fn child(self: ExpectedObjectPath) []const u8 {
        switch (self) {
            .@"/" => return "dev",
            .@"/dev" => return "sphaerophoria",
            .@"/dev/sphaerophoria" => return "TestService",
            .@"/dev/sphaerophoria/TestService" => unreachable,
        }
    }
};

pub fn ObjectApi(comptime Api: type) type {
    if (!@hasDecl(Api, "name")) {
        @compileError("Api needs name retrieval function");
    }

    if (!@hasDecl(Api, "definition")) {
        @compileError("Api needs definition retrieval function");
    }

    return struct {
        path: []const u8,
        api: Api,
    };
}

fn getDirectChildPathName(introspection_path: []const u8, service_path: []const u8) ?[]const u8 {
    if (service_path.len <= introspection_path.len) return null;

    const trimmed_introspection_path = std.mem.trimRight(u8, introspection_path, "/");
    std.debug.print("{s}: {s}\n", .{ service_path, trimmed_introspection_path });
    if (!std.mem.startsWith(u8, service_path, trimmed_introspection_path)) {
        return null;
    }

    const end_idx = std.mem.indexOfScalarPos(u8, service_path, trimmed_introspection_path.len + 1, '/') orelse service_path.len;
    const ret = service_path[trimmed_introspection_path.len + 1 .. end_idx];
    if (ret.len == 0) return null;
    return ret;
}

fn handleCommonDbusRequests(comptime Api: type, message: dbus.ParsedMessage, connection: *dbus.DbusConnection, services: []const ObjectApi(Api)) !?Api {
    const member = message.headers.member orelse return error.NoMember;
    const interface = message.headers.interface orelse return error.NoInterface;
    const path = message.headers.path orelse return error.NoPath;
    const sender = message.headers.sender orelse return error.NoSender;

    if (std.mem.eql(u8, interface.inner, "org.freedesktop.DBus.Introspectable") and std.mem.eql(u8, member.inner, "Introspect")) {
        var out_buf: [4096]u8 = undefined;
        var writer = std.Io.Writer.fixed(&out_buf);

        for (services) |service| {
            if (std.mem.eql(u8, service.path, path.inner)) {
                try connection.ret(message.serial, sender.inner, .{
                    dbus.DbusString{ .inner = service.api.definition() },
                });

                return null;
            }
            try writer.writeAll(
                \\<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
                \\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
                \\<node >
                \\
            );

            if (getDirectChildPathName(path.inner, service.path)) |name| {
                try writer.print(
                    \\<node name="{s}"/>
                    \\
                , .{name});
            }

            try writer.writeAll(
                \\</node>
            );
        }

        try connection.ret(message.serial, sender.inner, .{
            dbus.DbusString{ .inner = writer.buffered() },
        });

        return null;
    }

    for (services) |service| {
        if (std.mem.eql(u8, path.inner, service.path) and std.mem.eql(u8, service.api.name(), interface.inner)) {
            return service.api;
        }
    }

    try connection.err(
        message.serial,
        sender.inner,
        .{ .inner = "org.freedesktop.DBus.Error.UnknownObject" },
        dbus.DbusString{ .inner = "unknown object" },
    );

    return null;
}

fn writeResponse(message: dbus.ParsedMessage, connection: *dbus.DbusConnection) !void {
    const Api = struct {
        fn name(_: @This()) []const u8 {
            return "dev.sphaerophoria.TestService";
        }

        fn definition(_: @This()) []const u8 {
            return
            \\<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
            \\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
            \\<node >
            \\  <interface name="dev.sphaerophoria.TestService">
            \\    <method name="Hello">
            \\      <arg direction="out" type="s"/>
            \\    </method>
            \\  </interface>
            \\</node>
            ;
        }
    };

    const services = [_]ObjectApi(Api){
        .{
            .path = "/dev/sphaerophoria/TestService",
            .api = .{},
        },
    };

    _ = (try handleCommonDbusRequests(Api, message, connection, &services)) orelse return;

    const member = message.headers.member orelse return error.NoMember;
    const sender = message.headers.sender orelse return error.NoSender;

    if (!std.mem.eql(u8, member.inner, "Hello")) {
        try connection.err(
            message.serial,
            sender.inner,
            .{ .inner = "org.freedesktop.DBus.Error.UnknownMethod" },
            dbus.DbusString{ .inner = "unknown method" },
        );
    }


    try connection.ret(
        message.serial,
        sender.inner,
        dbus.DbusString{ .inner = "Hello world" },
    );
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

    while (true) {
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

        writeResponse(params, &connection) catch |e| switch (e) {
            error.WriteFailed => {
                std.log.info("IO failure, shutting down", .{});
                break;
            },
            error.OutOfMemory => {
                std.log.err("Internal oom error, dropping response", .{});
            },
            error.SerializeError => {
                std.log.err("Internal serialization error, dropping response", .{});
            },
            error.NoMember, error.NoInterface, error.NoPath, error.NoSender => {
                std.log.err("Invalid request ({t}), dropping response", .{e});
            },
            error.Uninitialized => unreachable,
        };
    }

    std.debug.print("done\n", .{});
}
