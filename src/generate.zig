const std = @import("std");
const sphtud = @import("sphtud");
const dbus = @import("sphdbus.zig");
const DbusSchemaParser = @import("DbusSchemaParser.zig");
const helpers = @import("generate_helpers.zig");

// node -> interface -> method

fn isTypeSupported(name: []const u8, typ: []const u8) bool {
    if (typ[0] == 'h') {
        std.log.warn("Do not yet support passing fds, {s} unsupported", .{name});
        return false;
    }

    var signature_reader = std.Io.Reader.fixed(typ);
    var tokenizer = dbus.SignatureTokenizer{
        .reader = &signature_reader,
        .diagnostics = null,
    };
    while (true) {
        _ = tokenizer.next() catch {
            std.log.warn("Failed to tokenize signature {s}, skipping method {s}", .{ typ, name });
            return false;
        } orelse break;
    }

    return true;
}

fn isPropertySupported(property: DbusSchemaParser.Property) bool {
    if (!isTypeSupported(property.name, property.typ)) return false;

    return true;
}

fn isMethodSupported(method: DbusSchemaParser.Method) bool {
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
    var dbus_parser = try DbusSchemaParser.init(root_alloc.allocator(), root_alloc.expansion());

    while (try parser.next(&content_writer.writer)) |item| {
        try dbus_parser.step(item);
    }

    var f_writer = std.Io.Writer.Allocating.init(root_alloc.allocator());
    try f_writer.writer.writeAll(
        \\const dbus = @import("sphdbus");
        \\const std = @import("std");
        \\
        \\
    );

    var interface_iter = dbus_parser.output.iter();
    while (interface_iter.next()) |interface| {
        try f_writer.writer.print(
            \\pub const {f} = struct {{
            \\
        , .{helpers.interfaceTypeName(interface.name)});

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
                    helpers.dbusToZigType(arg.typ),
                });
            }

            try f_writer.writer.writeAll(
                \\    };
                \\
            );
        }

        try f_writer.writer.print(
            \\            connection: *dbus.DbusConnection,
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
                \\
            , .{helpers.pascalToCamel(method.name)});

            var arg_it = method.args.iter();
            while (arg_it.next()) |arg| {
                try f_writer.writer.print(
                    \\                @"{s}": {f},
                    \\
                , .{
                    arg.name,
                    helpers.dbusToZigType(arg.typ),
                });
            }
            try f_writer.writer.print(
                \\            ) !dbus.CallHandle {{
                \\                return try self.connection.call(
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
                \\                );
                \\            }}
                \\
            , .{});

            if (method.ret.len > 0) {
                // Unimplemented, see parseGetPropertyResponse below
                unreachable;
            }
        }

        var property_it = interface.properties.iter();
        while (property_it.next()) |property| {
            if (!isPropertySupported(property.*)) continue;

            try f_writer.writer.print(
                \\            pub fn @"get{[property_name]s}"(
                \\                self: Self,
                \\            ) !dbus.CallHandle {{
                \\                return try self.connection.call(
                \\                    self.object_path,
                \\                    self.service,
                \\                    "org.freedesktop.DBus.Properties",
                \\                    "Get",
                \\                    .{{
                \\                          dbus.DbusString {{ .inner = "{[interface_name]s}" }},
                \\                          dbus.DbusString {{ .inner = "{[property_name]s}" }},
                \\                    }},
                \\                );
                \\            }}
                \\
                \\            pub fn @"parseGet{[property_name]s}Response"(
                \\                message: dbus.ParsedMessage,
                \\                options: dbus.ParseOptions,
                \\            ) !{[zig_type]f} {{
                \\                const v = try dbus.dbusParseBody(dbus.ParseVariant, message, options);
                \\                return v.toConcrete({[zig_type]f}, message.endianness, options);
                \\            }}
                \\
                \\            pub fn @"set{[property_name]s}Property"(
                \\                self: Self,
                \\                val: {[zig_type]f},
                \\            ) !void {{
                \\                _ = try self.connection.call(
                \\                    self.object_path,
                \\                    self.service,
                \\                    "org.freedesktop.DBus.Properties",
                \\                    "Set",
                \\                    .{{
                \\                          dbus.DbusString {{ .inner = "{[interface_name]s}" }},
                \\                          dbus.DbusString {{ .inner = "{[property_name]s}" }},
                \\                          dbus.serializationVariant(val),
                \\                    }},
                \\                );
                \\            }}
                \\
            , .{
                .property_name = property.name,
                .interface_name = interface.name,
                .zig_type = helpers.dbusToZigType(property.typ),
            });
        }

        try f_writer.writer.writeAll(
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
