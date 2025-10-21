const std = @import("std");
const sphtud = @import("sphtud");

// node -> interface -> method

const MethodArg = struct {
    typ: []const u8,
    name: []const u8,
};

const Method = struct {
    name: []const u8 = "",
    args: sphtud.util.RuntimeSegmentedListLinearAlloc(MethodArg) = .empty,
    ret: sphtud.util.RuntimeSegmentedListLinearAlloc(MethodArg) = .empty,

    pub fn init(alloc: std.mem.Allocator, name: []const u8) !Method {
        return .{
            .name = try alloc.dupe(u8, name),
            // FIXME: Update guesses
            .args = try .init(alloc, alloc, 100, 1000),
            // FIXME: Update guesses
            .ret = try .init(alloc, alloc, 100, 1000),
        };
    }
};

const Interface = struct {
    name: []const u8 = "",
    methods: sphtud.util.RuntimeSegmentedListLinearAlloc(Method) = .empty,

    pub fn init(alloc: std.mem.Allocator, name: []const u8) !Interface {
        return .{
            .name = try alloc.dupe(u8, name),
            // FIXME: update guesses,
            .methods = try .init(alloc, alloc, 100, 10000),
        };
    }
};

const DbusSchemaParser = struct {
    alloc: std.mem.Allocator,
    current_interface: Interface = .{},
    current_method: Method = .{},
    output: sphtud.util.RuntimeSegmentedListLinearAlloc(Interface),
    state: enum {
        default,
        interface,
        method,
    } = .default,

    fn step(self: *DbusSchemaParser, item: sphtud.xml.Item) !void {
        switch (self.state) {
            .default => try self.handleDefault(item),
            .interface => try self.handleInterface(item),
            .method => try self.handleMethod(item),
        }
    }

    fn handleDefault(self: *DbusSchemaParser, item: sphtud.xml.Item) !void {
        switch (item.type) {
            .element_start => {
                if (std.mem.eql(u8, item.name, "interface")) {
                    self.current_interface = try .init(
                        self.alloc,
                        (try item.attributeByKey("name")) orelse return error.NoInterfaceName,
                    );
                    self.state = .interface;
                }
            },
            else => {},
        }
    }

    fn handleInterface(self: *DbusSchemaParser, item: sphtud.xml.Item) !void {
        switch (item.type) {
            .element_start => {
                if (std.mem.eql(u8, item.name, "method")) {
                    self.current_method = try .init(
                        self.alloc,
                        (try item.attributeByKey("name")) orelse return error.NoMethodName,
                    );
                    self.state = .method;
                }

                // We do not handle nested interfaces yet
                std.debug.assert(!std.mem.eql(u8, item.name, "interface"));
            },
            .element_end => {
                // If we see nested interface we will fall over
                if (std.mem.eql(u8, item.name, "interface")) {
                    try self.output.append(self.current_interface);
                    self.current_interface = .{};
                    self.state = .default;
                }
            },
            else => {},
        }
    }

    fn handleMethod(self: *DbusSchemaParser, item: sphtud.xml.Item) !void {
        switch (item.type) {
            .element_start => {
                if (std.mem.eql(u8, item.name, "arg")) {
                    const dir = try item.attributeByKey("direction") orelse return error.NoDir;
                    const typ = try self.alloc.dupe(u8, try item.attributeByKey("type") orelse return error.NoType);
                    const name = try self.alloc.dupe(u8, try item.attributeByKey("name") orelse return error.NoName);
                    if (std.mem.eql(u8, dir, "in")) {
                        try self.current_method.args.append(.{
                            .typ = typ,
                            .name = name,
                        });
                    } else if (std.mem.eql(u8, dir, "out")) {
                        try self.current_method.ret.append(.{
                            .typ = typ,
                            .name = name,
                        });
                    }
                }
                // We do not handle nested methods yet
                std.debug.assert(!std.mem.eql(u8, item.name, "method"));
            },
            .element_end => {
                // If we see nested interface we will fall over
                if (std.mem.eql(u8, item.name, "method")) {
                    try self.current_interface.methods.append(self.current_method);
                    self.current_method = .{};
                    self.state = .interface;
                }
            },
            else => {},
        }
    }
};

const InterfaceTypeNameFormatter = struct {
    name: []const u8,

    pub fn format(self: InterfaceTypeNameFormatter, writer: *std.Io.Writer) !void {
        var it = std.mem.splitScalar(u8, self.name, '.');
        while (it.next()) |segment| {
            try writer.writeByte(std.ascii.toUpper(segment[0]));
            try writer.writeAll(segment[1..]);
        }
    }
};

fn interfaceTypeName(name: []const u8) InterfaceTypeNameFormatter {
    return .{ .name = name };
}

fn dbusToZigType(typ: []const u8) []const u8 {
    std.debug.assert(typ.len == 1);
    return switch (typ[0]) {
        'u' => "u32",
        'i' => "i32",
        't' => "u64",
        'o' => "dbus.DbusObject",
        's' => "dbus.DbusString",
        'b' => "bool",
        else => {
            std.log.err("Unhandled type {c}" ,.{typ[0]});
            unreachable;
        },
    };
}

fn isArgSupported(method: Method, arg: MethodArg) bool {
    if (arg.typ.len > 1) {
        std.log.warn("Unhandled type \"{s}\" for method {s}", .{arg.typ, method.name});
        return false;
    }

    if (arg.typ[0] == 'h') {
        std.log.warn("Do not yet support passing fds, {s} unsupported", .{method.name});
        return false;
    }

    return true;
}

fn isMethodSupported(method: Method) bool {
    var arg_it = method.args.iter();
    while (arg_it.next()) |arg| {
        if (!isArgSupported(method, arg.*)) return false;
    }

    var ret_it = method.ret.iter();
    while (ret_it.next()) |arg| {
        if (!isArgSupported(method, arg.*)) return false;
    }

    return true;
}

const PascalToCamelFormatter = struct {
    val: []const u8,

    pub fn format(self: PascalToCamelFormatter, writer: *std.Io.Writer) !void {
        try writer.writeByte(std.ascii.toLower(self.val[0]));
        try writer.writeAll(self.val[1..]);
    }
};

fn pascalToCamel(val: []const u8) PascalToCamelFormatter {
    return .{ .val = val };
}

pub fn main() !void {
    var alloc_buf: [2 * 1024 * 1024]u8 = undefined;
    var root_alloc = sphtud.alloc.BufAllocator.init(&alloc_buf);

    const args = try std.process.argsAlloc(root_alloc.allocator());
    const schema_path = args[1];
    const output_path = args[2];

    const f = try std.fs.cwd().openFile(schema_path, .{});
    var f_reader = f.reader(try root_alloc.allocator().alloc(u8, 4096));

    var out_f = try std.fs.cwd().createFile(output_path, .{});
    var f_writer = out_f.writer(try root_alloc.allocator().alloc(u8, 4096));

    var content_writer = std.Io.Writer.Discarding.init(&.{});
    var parser = sphtud.xml.Parser.init(&f_reader.interface);
    var dbus_parser = DbusSchemaParser{
        .alloc = root_alloc.allocator(),
        .output = try .init(
            root_alloc.allocator(),
            root_alloc.allocator(),
            // FIXME: Sane guesses please :)
            100,
            1000,
        ),
    };
    while (try parser.next(&content_writer.writer)) |item| {
        try dbus_parser.step(item);
    }

    try f_writer.interface.writeAll(
        // FIXME: Better path
        \\const dbus = @import("main.zig");
        \\
        \\fn generateCommonResponseHandler(comptime T: type, ctx: ?*anyopaque, comptime callback: *const fn(ctx: ?*anyopaque, T) anyerror!void) dbus.CompletionHandler {
        \\    const genericCb = struct {
        \\        fn f(ctx_2: ?*anyopaque, endianness: dbus.DbusEndianness, signature: []const u8, body: []const u8) !void {
        \\            const val = try dbus.dbusParseBody(T, endianness, signature, body);
        \\            try callback(ctx_2, val);
        \\        }
        \\    }.f;
        \\
        \\    return .{
        \\        .ctx = ctx,
        \\        .vtable = &.{
        \\            .onFinish = genericCb,
        \\        },
        \\    };
        \\}
        \\
        \\
    );

    var interface_iter = dbus_parser.output.iter();
    while (interface_iter.next()) |interface| {
        if (!std.mem.eql(u8, interface.name, "org.freedesktop.login1.Manager")) {
            continue;
        }

        try f_writer.interface.print(
            \\pub const {f} = struct {{
            \\
            , .{interfaceTypeName(interface.name)}
        );

        var method_it = interface.methods.iter();
        while (method_it.next()) |method| {
            if (!isMethodSupported(method.*)) {
                continue;
            }

            try f_writer.interface.print(
                \\    pub const {s}Response = struct {{
                \\
                , .{method.name}
            );

            var ret_it = method.ret.iter();
            while (ret_it.next()) |arg| {
                try f_writer.interface.print(
                    \\        {s}: {s},
                    \\
                , .{
                    arg.name,
                    dbusToZigType(arg.typ),
                });
            }

            try f_writer.interface.writeAll(
                \\    };
                \\
            );
        }

        try f_writer.interface.writeAll(
            \\    pub fn interface(connection: anytype, service: []const u8, object_path: []const u8) Interface(@TypeOf(connection)) {{
            \\        return .{
            \\            .connection = connection,
            \\            .service = service,
            \\            .object_path = object_path,
            \\        };
            \\    }}
            \\
            \\    pub fn Interface(comptime ConnectionType: type) type {
            \\        return struct {
            \\            connection: ConnectionType,
            \\            service: []const u8,
            \\            object_path: []const u8,

            \\            const interface_name = "org.freedesktop.login1.Manager";

            \\            const Self = @This();
            \\
            \\
        );

        method_it = interface.methods.iter();
        while (method_it.next()) |method| {
            if (!isMethodSupported(method.*)) continue;
            try f_writer.interface.print(
                \\            pub fn {f}(
                \\                self: Self,
                \\
                , .{pascalToCamel(method.name)}
            );

            var arg_it = method.args.iter();
            while (arg_it.next()) |arg| {
                try f_writer.interface.print(
                    \\                {s}: {s},
                    \\
                    , .{
                        arg.name,
                        dbusToZigType(arg.typ),
                    }
                );
            }
            try f_writer.interface.print(
                \\                on_response_ctx: ?*anyopaque,
                \\                comptime on_response_callback: ?*const fn(ctx: ?*anyopaque, {0s}Response) anyerror!void,
                \\            ) !void {{
                \\                try self.connection.call(
                \\                    self.object_path,
                \\                    self.service,
                \\                    interface_name,
                \\                    "{0s}",
                \\                    .{{
                \\
                ,
                .{
                    method.name,
                }
            );

            arg_it = method.args.iter();
            while (arg_it.next()) |arg| {
                try f_writer.interface.print(
                    \\                        {s},
                    \\
                    , .{
                        arg.name,
                    }
                );
            }

            try f_writer.interface.print(
                \\                    }},
                \\                    if (on_response_callback) |c| generateCommonResponseHandler({s}Response, on_response_ctx, c) else null,
                \\                );
                \\            }}
                \\
                ,
                .{method.name}

            );

        }

        try f_writer.interface.writeAll(
            \\        };
            \\    }
            \\};
            \\
        );
    }

    try f_writer.interface.flush();
}
