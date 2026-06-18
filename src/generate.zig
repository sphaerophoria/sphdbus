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

    var tokenizer = dbus.SignatureTokenizer{
        .reader = .fixed(typ),
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

pub fn main(init: std.process.Init.Minimal) !void {
    var alloc_buf: [4 * 1024 * 1024]u8 = undefined;
    var root_alloc = sphtud.alloc.BufAllocator.init(&alloc_buf);
    const scratch = root_alloc.backLinear();

    const args = try init.args.toSlice(root_alloc.allocator());
    const schema_path = args[1];
    const output_path = args[2];

    const f = try sphtud.io.open(schema_path, .{}, 0);
    var f_reader = sphtud.io.Reader.init(f, try root_alloc.allocator().alloc(u8, 4096));

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
                \\                buf: []u8,
                \\            ) !dbus.CallHandle {{
                \\                var bs: dbus.BodySerializer = undefined;
                \\                bs.initPinned(buf);
                \\                try bs.addTyped(.{{
            , .{});

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
                \\                return try self.connection.call(
                \\                    self.object_path,
                \\                    self.service,
                \\                    interface_name_to_serialize,
                \\                    "{0s}",
                \\                    &bs,
                \\                );
                \\            }}
                \\
            , .{
                method.name,
            });

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
                \\                buf: []u8,
                \\            ) !dbus.CallHandle {{
                \\                var bs: dbus.BodySerializer = undefined;
                \\                bs.initPinned(buf);
                \\                try bs.addTyped(.{{
                \\                      dbus.DbusString {{ .inner = "{[interface_name]s}" }},
                \\                      dbus.DbusString {{ .inner = "{[property_name]s}" }},
                \\                }});
                \\                return try self.connection.call(
                \\                    self.object_path,
                \\                    self.service,
                \\                    "org.freedesktop.DBus.Properties",
                \\                    "Get",
                \\                    &bs,
                \\                );
                \\            }}
                \\
                \\            pub fn @"parseGet{[property_name]s}Response"(
                \\                message: dbus.ParsedMessage,
                \\                options: dbus.ParseOptions,
                \\            ) !{[zig_type]f} {{
                \\                var br = try dbus.BodyReader.initMessage(message, options);
                \\                var v = try br.nextVariant();
                \\                return v.nextTyped({[zig_type]f});
                \\            }}
                \\
                \\            pub fn @"set{[property_name]s}Property"(
                \\                self: Self,
                \\                buf: []u8,
                \\                val: {[zig_type]f},
                \\            ) !void {{
                \\                var bs: dbus.BodySerializer = undefined;
                \\                bs.initPinned(buf);
                \\                try bs.addTyped(.{{
                \\                      dbus.DbusString {{ .inner = "{[interface_name]s}" }},
                \\                      dbus.DbusString {{ .inner = "{[property_name]s}" }},
                \\                      dbus.serializationVariant(val),
                \\                }});
                \\                _ = try self.connection.call(
                \\                    self.object_path,
                \\                    self.service,
                \\                    "org.freedesktop.DBus.Properties",
                \\                    "Set",
                \\                    &bs,
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
    const out_f = try sphtud.io.open(output_path, .{ .ACCMODE = .RDWR, .CREAT = true, .TRUNC = true }, 0o664);
    var actual_f_writer = sphtud.io.Writer.init(out_f, try root_alloc.allocator().alloc(u8, 4096));
    try parsed.render(root_alloc.allocator(), &actual_f_writer.interface, .{});
    //try actual_f_writer.interface.writeAll(written_sentinel);
    try actual_f_writer.interface.flush();
}
