const std = @import("std");
const sphtud = @import("sphtud");
const builtin = @import("builtin");
const dbus = @import("sphdbus");
const mpris = @import("mpris");

fn waitForResponse(connection: *dbus.DbusConnection, handle: dbus.DbusConnection.CallHandle) !void {
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

const DbusHandlerError = error {
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
    const member = try message.getHeader(.member) orelse return error.InvalidCall;
    const interface = try message.getHeader(.interface) orelse return error.InvalidCall;

    if (!interface.eql(.{ .string = "org.freedesktop.DBus.Introspectable" })) {
        return error.Unimplemented;
    }

    if (!member.eql(.{ .string = "Introspect" })) {
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
    const sender = (try message.getHeader(.sender)).?.string;

    try connection.ret(message.serial, sender, .{
        dbus.DbusString { .inner = writer.buffered() },
    });
}

fn writeResponse(message: dbus.ParsedMessage, connection: *dbus.DbusConnection) DbusHandlerError!void {
    const path = (try message.getHeader(.path)) orelse return error.NoPath;
    // FIXME: Crashy crashy
    const parsed_path = std.meta.stringToEnum(ExpectedObjectPath, path.object) orelse return error.UnexpectedPath;

    switch (parsed_path) {
        .@"/", .@"/dev", .@"/dev/sphaerophoria" => try handleIntrospectionOnlyPath(message, parsed_path, connection),
        .@"/dev/sphaerophoria/TestService" => {
            const Interface = enum {
                @"org.freedesktop.DBus.Introspectable",
                @"dev.sphaerophoria.TestService",
            };

            const interface = (try message.getHeader(.interface)) orelse return error.InvalidCall;
            if (interface != .string) return error.InvalidCall;

            const member = try message.getHeader(.member) orelse return error.InvalidCall;

            const parsed_interface = std.meta.stringToEnum(Interface, interface.string) orelse return error.Unimplemented;
            switch (parsed_interface) {
                .@"org.freedesktop.DBus.Introspectable" => {
                    if (!member.eql(.{ .string = "Introspect" })) {
                        return error.Unimplemented;
                    }

                    // FIXME: Crashy crashy crashy
                    const sender = (try message.getHeader(.sender)).?.string;

                    try connection.ret(message.serial, sender, .{
                        dbus.DbusString { .inner = api },
                    });

                },
                .@"dev.sphaerophoria.TestService" => {
                    if (member != .string) return error.InvalidCall;
                    if (!std.mem.eql(u8, member.string, "Hello")) {
                        return error.Unimplemented;
                    }

                    // FIXME: Crashy crashy crashy
                    const sender = (try message.getHeader(.sender)).?.string;

                    try connection.ret(message.serial, sender, .{
                        dbus.DbusString { .inner = "Hello from dbus service" },
                    });
                },


            }
        },
    }
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
            dbus.DbusString { .inner = "dev.sphaerophoria.TestService" },
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

        std.debug.print("someone is asking us for something {any}\n", .{params});
        try writeResponse(params, &connection);

    }

    std.debug.print("done\n", .{});
}
