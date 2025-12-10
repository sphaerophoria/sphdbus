const std = @import("std");
const sphtud = @import("sphtud");
const builtin = @import("builtin");
const dbus = @import("sphdbus");
const mpris = @import("mpris");

fn waitForResponse(connection: *dbus.DbusConnection, handle: dbus.CallHandle) !void {
    while (true) {
        const res = try connection.poll();
        const response = switch (res) {
            .response => |r| r,
            else => continue,
        };

        if (response.handle.inner == handle.inner) break;
    }
}

const service_object = "/dev/sphaerophoria/TestService";

// FIXME: This seems unreasonable. Less errors and more diagnostics might be a
// better play
//
// Errors that result in returning an error to the caller
//    * Error message and dbus type conversion
// Errors that result in us shutting down our dbus connection
// Errors that are unrecoverable?
// Blocking/nonblocking errors
const DbusHandlerError = error{
    InvalidHeaderField,
    // FIXME: Path -> Object?
    NoPath,
    UnexpectedPath,
    Unimplemented,
    OutOfMemory,
    UnknownTag,
    InvalidLen,
    Uninitialized,
    InvalidCall,
    InvalidSignature,
    UnhandledSignature,
    InvalidArraySignature,
    NoMember,
    NoInterface,
    NoHandler,
} || std.Io.Writer.Error || std.Io.Reader.Error;

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

fn handleIntrospectionOnlyPath(message: dbus.ParsedMessage, path: ExpectedObjectPath, connection: *dbus.DbusConnection) DbusHandlerError!void {
    // FIXME: Why would we iterate the header list once per field idiot
    const member = try message.getHeader(.member) orelse return error.InvalidCall;
    const interface = try message.getHeader(.interface) orelse return error.InvalidCall;

    if (!std.mem.eql(u8, interface.inner, "org.freedesktop.DBus.Introspectable")) {
        return error.Unimplemented;
    }

    if (!std.mem.eql(u8, member.inner, "Introspect")) {
        return error.Unimplemented;
    }

    var out_buf: [4096]u8 = undefined;
    var writer = std.Io.Writer.fixed(&out_buf);
    try writer.print(
        \\<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
        \\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
        \\<node >
        \\  <node name="{s}"/>
        \\</node>
    , .{path.child()});

    // FIXME: Crashy crashy crashy
    const sender = (try message.getHeader(.sender)).?.inner;

    try connection.ret(message.serial, sender, .{
        dbus.DbusString{ .inner = writer.buffered() },
    });
}

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

    if (!std.mem.startsWith(u8, service_path, introspection_path)) {
        return null;
    }

    const end_idx = std.mem.indexOfScalarPos(u8, service_path, introspection_path.len, '/') orelse service_path.len;
    return service_path[introspection_path.len..end_idx];
}

fn handleCommonDbusRequests(comptime Api: type, message: dbus.ParsedMessage, connection: *dbus.DbusConnection, services: []const ObjectApi(Api)) !?Api {
    const member = (try message.getHeader(.member)) orelse return error.NoMember;
    const interface = (try message.getHeader(.interface)) orelse return error.NoInterface;
    const path = (try message.getHeader(.path)) orelse return error.NoPath;

    if (std.mem.eql(u8, interface.inner, "org.freedesktop.DBus.Introspectable") and std.mem.eql(u8, member.inner, "Introspect")) {
        var out_buf: [4096]u8 = undefined;
        var writer = std.Io.Writer.fixed(&out_buf);

        for (services) |service| {
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

        // FIXME: Crashy crashy crashy
        const sender = (try message.getHeader(.sender)).?.inner;

        std.debug.print("intrpsection response\n{s}", .{writer.buffered()});
        try connection.ret(message.serial, sender, .{
            dbus.DbusString{ .inner = writer.buffered() },
        });

        // Is path that they gave us an ancestor of any of our paths

        return null;
    }

    for (services) |service| {
        if (std.mem.eql(u8, path.inner, service.path) and std.mem.eql(u8, service.api.name(), interface.inner)) {
            return service.api;
        }
    }

    return error.NoHandler;
}

fn writeResponse(message: dbus.ParsedMessage, connection: *dbus.DbusConnection) DbusHandlerError!void {
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

    // FIXME: duplicated?
    const member = (try message.getHeader(.member)) orelse return error.NoMember;
    if (!std.mem.eql(u8, member.inner, "Hello")) {
        return error.Unimplemented;
    }

    // FIXME: Crashy crashy crashy
    const sender = (try message.getHeader(.sender)).?.inner;

    try connection.err(
        message.serial,
        sender,
        .{ .inner = "dev.sphaerophoria.TestService.Error" },
        dbus.DbusString{ .inner = "Something went terribly wrong" },
    );
}

const api =
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

pub fn main() !void {
    var alloc_buf: [1 * 1024 * 1024]u8 = undefined;
    var buf_alloc = sphtud.alloc.BufAllocator.init(&alloc_buf);

    const alloc = buf_alloc.allocator();

    const stream = try dbus.sessionBus();

    const reader = try alloc.create(std.net.Stream.Reader);
    reader.* = stream.reader(try alloc.alloc(u8, 4096));

    const writer = try alloc.create(std.net.Stream.Writer);
    writer.* = stream.writer(try alloc.alloc(u8, 4096));

    var connection = try dbus.dbusConnection(reader.interface(), &writer.interface);
    while (try connection.poll() != .initialized) {}

    // FIXME: This needs a nice API somewhere probably...
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

    try waitForResponse(&connection, handle);

    while (true) {
        const res = try connection.poll();
        const params = switch (res) {
            .call => |params| params,
            else => continue,
        };

        // Dbus service
        //
        // RecoverableError -- Report error somehow?
        // FatalError -- I've parsed 1/10th of a packet and don't know how to consume the rest
        //
        // Packet parse

        std.debug.print("someone is asking us for something {any}\n", .{params});
        try writeResponse(params, &connection);
    }

    std.debug.print("done\n", .{});
}
