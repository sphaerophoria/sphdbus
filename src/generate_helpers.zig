const std = @import("std");
const dbus = @import("sphdbus.zig");

pub const InterfaceTypeNameFormatter = struct {
    name: []const u8,

    pub fn format(self: InterfaceTypeNameFormatter, writer: *std.Io.Writer) !void {
        var it = std.mem.splitScalar(u8, self.name, '.');
        while (it.next()) |segment| {
            try writer.writeByte(std.ascii.toUpper(segment[0]));
            try writer.writeAll(segment[1..]);
        }
    }
};

pub fn interfaceTypeName(name: []const u8) InterfaceTypeNameFormatter {
    return .{ .name = name };
}

pub const DbusToZigTypeFormatter = struct {
    typ: []const u8,

    pub fn format(self: DbusToZigTypeFormatter, writer: *std.Io.Writer) !void {
        var reader = std.Io.Reader.fixed(self.typ);
        var tokenizer = dbus.SignatureTokenizer{
            .reader = &reader,
            .diagnostics = null,
        };

        // FIXME: Very similar to variant parsing code
        const Tag = enum {
            array,
            @"struct",
        };

        var tag_stack_buf: [10]Tag = undefined;
        var tag_stack = std.ArrayList(Tag).initBuffer(&tag_stack_buf);

        while (true) {
            const tag = tokenizer.next() catch {
                return error.WriteFailed;
            } orelse break;

            switch (tag) {
                .array_start => {
                    try writer.writeAll("dbus.ParseArray(");
                    tag_stack.appendBounded(.array) catch unreachable;
                },
                .struct_start => {
                    try writer.writeAll("struct {");
                    tag_stack.appendBounded(.@"struct") catch unreachable;
                },
                .struct_end => {
                    try writer.writeAll("}");
                    const last_elem = tag_stack.pop();
                    std.debug.assert(last_elem == .@"struct");
                },
                .kv_start => {
                    try writer.writeAll("dbus.DbusKV(");
                    tag_stack.appendBounded(.@"struct") catch unreachable;
                },
                .kv_end => {
                    try writer.writeAll(")");
                    const last_elem = tag_stack.pop();
                    std.debug.assert(last_elem == .@"struct");
                },
                .u32 => try writer.writeAll("u32"),
                .u64 => try writer.writeAll("u64"),
                .i32 => try writer.writeAll("i32"),
                .i64 => try writer.writeAll("i64"),
                .f64 => try writer.writeAll("f64"),
                .object => try writer.writeAll("dbus.DbusObject"),
                .string => try writer.writeAll("dbus.DbusString"),
                .bool => try writer.writeAll("bool"),
                .variant => try writer.writeAll("dbus.ParseVariant"),
                .signature => try writer.writeAll("dbus.DbusSignature"),
            }

            switch (tag) {
                .array_start, .struct_start, .kv_start => {},
                else => {
                    const last_elem = tag_stack.getLastOrNull();
                    if (last_elem == .@"struct") {
                        try writer.writeAll(", ");
                    } else if (last_elem == .array) {
                        try writer.writeAll(")");
                        _ = tag_stack.pop();
                    }
                },
            }
        }
    }
};

pub fn dbusToZigType(typ: []const u8) DbusToZigTypeFormatter {
    return .{ .typ = typ };
}

pub const PascalToCamelFormatter = struct {
    val: []const u8,

    pub fn format(self: PascalToCamelFormatter, writer: *std.Io.Writer) !void {
        try writer.writeByte(std.ascii.toLower(self.val[0]));
        try writer.writeAll(self.val[1..]);
    }
};

pub fn pascalToCamel(val: []const u8) PascalToCamelFormatter {
    return .{ .val = val };
}
