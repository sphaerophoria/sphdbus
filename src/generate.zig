const std = @import("std");
const sphtud = @import("sphtud");
const dbus = @import("sphdbus.zig");

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
    properties: sphtud.util.RuntimeSegmentedListLinearAlloc(Property) = .empty,

    pub fn init(alloc: std.mem.Allocator, name: []const u8) !Interface {
        return .{
            .name = try alloc.dupe(u8, name),
            // FIXME: update guesses,
            .methods = try .init(alloc, alloc, 100, 10000),
            .properties = try .init(alloc, alloc, 100, 10000),
        };
    }
};

const Property = struct {
    name: []const u8 = "",
    typ: []const u8 = "",
    access: PropertyAccess = .read,

    const PropertyAccess = enum {
        read,
        readwrite,
    };
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

                if (std.mem.eql(u8, item.name, "property")) {
                    const name = (try item.attributeByKey("name")) orelse return error.NoPropertyName;
                    const typ = (try item.attributeByKey("type")) orelse return error.NoPropertyType;
                    const access_s = (try item.attributeByKey("access")) orelse return error.NoPropertyAccess;

                    const access = std.meta.stringToEnum(Property.PropertyAccess, access_s) orelse return error.UnimplementedAccess;
                    try self.current_interface.properties.append(.{
                        .access = access,
                        .typ = try self.alloc.dupe(u8, typ),
                        .name = try self.alloc.dupe(u8, name),
                    });
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

const DbusToZigTypeFormatter = struct {
    typ: []const u8,

    pub fn format(self: DbusToZigTypeFormatter, writer: *std.Io.Writer) !void {
        var reader = std.Io.Reader.fixed(self.typ);
        var tokenizer = dbus.SignatureTokenizer{
            .reader = &reader,
        };

        var in_struct = false;

        while (true) {
            const tag = tokenizer.next() catch {
                return error.WriteFailed;
            } orelse break;

            switch (tag) {
                .array_start => {
                    try writer.writeAll("[]");
                },
                .struct_start => {
                    // upgrade to stack on failure
                    std.debug.assert(in_struct == false);
                    try writer.writeAll("struct {");
                    in_struct = true;
                },
                .struct_end => {
                    try writer.writeAll("}");
                    in_struct = false;
                },
                .kv_start => {
                    // upgrade to stack on failure
                    std.debug.assert(in_struct == false);
                    try writer.writeAll("dbus.DbusKV(");
                    in_struct = true;
                },
                .kv_end => {
                    try writer.writeAll(")");
                    in_struct = false;
                },
                .u32 => try writer.writeAll("u32"),
                .u64 => try writer.writeAll("u64"),
                .i32 => try writer.writeAll("i32"),
                .i64 => try writer.writeAll("i64"),
                .f64 => try writer.writeAll("f64"),
                .object => try writer.writeAll("dbus.DbusObject"),
                .string => try writer.writeAll("dbus.DbusString"),
                .bool => try writer.writeAll("bool"),
                .variant => try writer.writeAll("dbus.Variant"),
            }

            switch (tag) {
                .array_start, .struct_start, .kv_start => {},
                else => {
                    if (in_struct) {
                        try writer.writeAll(", ");
                    }
                },
            }
        }
    }
};

fn dbusToZigType(typ: []const u8) DbusToZigTypeFormatter {
    return .{ .typ = typ };
}

fn isTypeSupported(name: []const u8, typ: []const u8) bool {
    if (typ[0] == 'h') {
        std.log.warn("Do not yet support passing fds, {s} unsupported", .{name});
        return false;
    }

    var signature_reader = std.Io.Reader.fixed(typ);
    var tokenizer = dbus.SignatureTokenizer{ .reader = &signature_reader };
    while (true) {
        _ = tokenizer.next() catch {
            std.log.warn("Failed to tokenize signature {s}, skipping method {s}", .{ typ, name });
            return false;
        } orelse break;
    }

    return true;
}

fn isPropertySupported(property: Property) bool {
    if (!isTypeSupported(property.name, property.typ)) return false;

    return true;
}

fn isMethodSupported(method: Method) bool {
    var arg_it = method.args.iter();
    while (arg_it.next()) |arg| {
        if (!isTypeSupported(method.name, arg.typ)) return false;
    }

    var ret_it = method.ret.iter();
    while (ret_it.next()) |arg| {
        if (!isTypeSupported(method.name, arg.typ)) return false;
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

const ReservedWords = enum {
    @"suspend",
    type,
};

fn dodgeReservedKeyword(val: []const u8) []const u8 {
    const tag = std.meta.stringToEnum(ReservedWords, val) orelse return val;
    return switch (tag) {
        .@"suspend" => "@\"suspend\"",
        .type => "typ",
    };
}

pub fn main() !void {
    var alloc_buf: [4 * 1024 * 1024]u8 = undefined;
    var root_alloc = sphtud.alloc.BufAllocator.init(&alloc_buf);
    const scratch = root_alloc.backLinear();

    const args = try std.process.argsAlloc(root_alloc.allocator());
    const schema_path = args[1];
    const output_path = args[2];

    const f = try std.fs.cwd().openFile(schema_path, .{});
    var f_reader = f.reader(try root_alloc.allocator().alloc(u8, 4096));

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

    var f_writer = std.Io.Writer.Allocating.init(root_alloc.allocator());
    try f_writer.writer.writeAll(
        \\const dbus = @import("sphdbus");
        \\const sphtud = @import("sphtud");
        \\const std = @import("std");
        \\
        \\
    );

    var interface_iter = dbus_parser.output.iter();
    while (interface_iter.next()) |interface| {
        try f_writer.writer.print(
            \\pub const {f} = struct {{
            \\
        , .{interfaceTypeName(interface.name)});

        var method_it = interface.methods.iter();
        while (method_it.next()) |method| {
            const cp = scratch.checkpoint();
            defer scratch.restore(cp);

            if (!isMethodSupported(method.*)) {
                continue;
            }

            try f_writer.writer.print(
                \\    pub const {s}Response = struct {{
                \\
            , .{method.name});

            var ret_it = method.ret.iter();
            while (ret_it.next()) |arg| {
                try f_writer.writer.print(
                    \\        {s}: {f},
                    \\
                , .{
                    arg.name,
                    dbusToZigType(arg.typ),
                });
            }

            try f_writer.writer.writeAll(
                \\    };
                \\
            );
        }

        try f_writer.writer.print(
            \\    pub fn interface(connection: anytype, service: []const u8, object_path: []const u8) Interface(@TypeOf(connection)) {{
            \\        return .{{
            \\            .connection = connection,
            \\            .service = service,
            \\            .object_path = object_path,
            \\        }};
            \\    }}
            \\
            \\    pub fn Interface(comptime ConnectionType: type) type {{
            \\        return struct {{
            \\            connection: ConnectionType,
            \\            service: []const u8,
            \\            object_path: []const u8,
            \\            const interface_name_to_serialize = "{s}";
            \\            const Self = @This();
            \\
            \\
        , .{interface.name});

        method_it = interface.methods.iter();
        while (method_it.next()) |method| {
            if (!isMethodSupported(method.*)) continue;
            try f_writer.writer.print(
                \\            pub fn @"{f}"(
                \\                self: Self,
                \\                writer: *std.Io.Writer,
                \\
            , .{pascalToCamel(method.name)});

            var arg_it = method.args.iter();
            while (arg_it.next()) |arg| {
                try f_writer.writer.print(
                    \\                @"{s}": {f},
                    \\
                , .{
                    arg.name,
                    dbusToZigType(arg.typ),
                });
            }
            try f_writer.writer.print(
                \\                on_response_ctx: ?*anyopaque,
                \\                comptime on_response_callback: ?*const fn(ctx: ?*anyopaque, {0s}Response) anyerror!void,
                \\            ) !void {{
                \\                try self.connection.call(
                \\                    writer,
                \\                    self.object_path,
                \\                    self.service,
                \\                    interface_name_to_serialize,
                \\                    "{0s}",
                \\                    .{{
                \\
            , .{
                method.name,
            });

            arg_it = method.args.iter();
            while (arg_it.next()) |arg| {
                try f_writer.writer.print(
                    \\                        @"{s}",
                    \\
                , .{
                    arg.name,
                });
            }

            try f_writer.writer.print(
                \\                    }},
                \\                    if (on_response_callback) |c| dbus.generateCommonResponseHandler({s}Response, on_response_ctx, c) else null,
                \\                );
                \\            }}
                \\
            , .{method.name});
        }

        var property_it = interface.properties.iter();
        while (property_it.next()) |property| {
            if (!isPropertySupported(property.*)) continue;
            try f_writer.writer.print(
                \\            pub fn @"get{0s}"(
                \\                self: Self,
                \\                writer: *std.Io.Writer,
                \\                on_response_ctx: ?*anyopaque,
                \\                comptime on_response_callback: ?*const fn(ctx: ?*anyopaque, {2f}) anyerror!void,
                \\            ) !void {{
                \\                try self.connection.call(
                \\                    writer,
                \\                    self.object_path,
                \\                    self.service,
                \\                    "org.freedesktop.DBus.Properties",
                \\                    "Get",
                \\                    .{{
                \\                          dbus.DbusString {{ .inner = "{1s}" }},
                \\                          dbus.DbusString {{ .inner = "{0s}" }},
                \\                    }},
                \\                    if (on_response_callback) |c| dbus.generateCommonResponseHandlerVariant({2f}, on_response_ctx, c) else null,
                \\                );
                \\            }}
                \\
                \\            pub fn @"set{0s}Property"(
                \\                self: Self,
                \\                writer: *std.Io.Writer,
                \\                val: {2f},
                \\            ) !void {{
                \\                try self.connection.call(
                \\                    writer,
                \\                    self.object_path,
                \\                    self.service,
                \\                    "org.freedesktop.DBus.Properties",
                \\                    "Set",
                \\                    .{{
                \\                          dbus.DbusString {{ .inner = "{1s}" }},
                \\                          dbus.DbusString {{ .inner = "{0s}" }},
                \\                          try dbus.Variant.fromConcrete(val),
                \\                    }},
                \\                    null,
                \\                );
                \\            }}
                \\
            , .{
                property.name,
                interface.name,
                dbusToZigType(property.typ),
            });
        }

        try f_writer.writer.writeAll(
            \\        };
            \\    }
            \\};
            \\
        );
    }

    // To make ast parse happy
    try f_writer.writer.writeByte(0);
    try f_writer.writer.flush();

    const written = f_writer.written();
    const written_sentinel = written[0 .. written.len - 1 :0];
    const parsed = try std.zig.Ast.parse(root_alloc.allocator(), written_sentinel, .zig);
    var out_f = try std.fs.cwd().createFile(output_path, .{});
    var actual_f_writer = out_f.writer(try root_alloc.allocator().alloc(u8, 4096));
    try parsed.render(root_alloc.allocator(), &actual_f_writer.interface, .{});
    //try actual_f_writer.interface.writeAll(written_sentinel);
    try actual_f_writer.interface.flush();
}
