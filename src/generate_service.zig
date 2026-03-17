const std = @import("std");
const sphtud = @import("sphtud");
const DbusSchemaParser = @import("DbusSchemaParser.zig");
const helpers = @import("generate_helpers.zig");

fn LinkedIndentPrinter(indent_level: usize) type {
    return struct {
        w: *std.Io.Writer,
        wants_indent: *bool,

        const indent_start = "    " ** indent_level;

        pub fn indent(self: @This()) LinkedIndentPrinter(indent_level + 1) {
            return .{
                .w = self.w,
                .wants_indent = self.wants_indent,
            };
        }

        fn print(self: @This(), comptime fmt: []const u8, args: anytype) !void {
            const new_fmt = comptime blk: {
                var new_fmt: []const u8 = "";
                var it = std.mem.splitScalar(u8, fmt, '\n');

                if (it.next()) |first| {
                    // First line does not get indent in comptime block as we
                    // don't know if we want to indent until we have runtime
                    // info
                    new_fmt = first;
                }

                while (it.next()) |line| {
                    if (line.len > 0) {
                        new_fmt = new_fmt ++ "\n" ++ indent_start ++ line;
                    } else {
                        new_fmt = new_fmt ++ "\n";
                    }
                }
                break :blk new_fmt;
            };

            if (self.wants_indent.*) {
                try self.w.writeAll(indent_start);
            }
            // This doesn't handle the case where fmt ends with a string and
            // the arg ends with a newline. That seems way harder to implement
            // though, so this is good enough for now
            self.wants_indent.* = endsWithNewline(fmt);

            try self.w.print(new_fmt, args);
        }

        fn writeAll(self: @This(), data: []const u8) !void {
            var it = std.mem.splitScalar(u8, data, '\n');

            if (it.next()) |line| {
                if (self.wants_indent.*) {
                    try self.writeIndentedLine(line);
                } else {
                    try self.w.writeAll(line);
                }
            }

            while (it.next()) |line| {
                try self.w.writeByte('\n');
                try self.writeIndentedLine(line);
            }

            self.wants_indent.* = endsWithNewline(data);
        }

        fn writeIndentedLine(self: @This(), line: []const u8) !void {
            if (line.len > 0) {
                try self.w.writeAll(indent_start);
                try self.w.writeAll(line);
            }
        }

        fn endsWithNewline(buf: []const u8) bool {
            if (buf.len == 0) return false;
            return buf[buf.len - 1] == '\n';
        }
    };
}

fn IndentPrinter(indent_level: usize) type {
    return struct {
        w: *std.Io.Writer,
        wants_indent: bool,

        const indent_start = "    " ** indent_level;

        pub fn indent(self: *@This()) LinkedIndentPrinter(indent_level + 1) {
            return .{
                .w = self.w,
                .wants_indent = &self.wants_indent,
            };
        }

        fn linked(self: *@This()) LinkedIndentPrinter(indent_level) {
            return .{
                .w = self.w,
                .wants_indent = &self.wants_indent,
            };
        }

        pub fn print(self: *@This(), comptime fmt: []const u8, args: anytype) !void {
            try self.linked().print(fmt, args);
        }

        fn writeAll(self: *@This(), data: []const u8) !void {
            try self.linked().writeAll(data);
        }
    };
}

test "indent writer" {
    var buf: [4096]u8 = undefined;

    {
        var w = std.Io.Writer.fixed(&buf);
        var iw = indentPrinter(&w, 1);
        try iw.print(
            \\Hello {s}
            \\it is a good day
            \\
        , .{"friend"});

        try std.testing.expectEqualStrings(
            \\    Hello friend
            \\    it is a good day
            \\
        , w.buffered());
    }

    {
        var w = std.Io.Writer.fixed(&buf);
        var iw = indentPrinter(&w, 1);
        try iw.writeAll("Hello ");
        try iw.writeAll("friend\n");
        try iw.writeAll("it is a good day\n");

        try std.testing.expectEqualStrings(
            \\    Hello friend
            \\    it is a good day
            \\
        , w.buffered());
    }
}

fn indentPrinter(w: *std.Io.Writer, comptime indent_level: usize) IndentPrinter(indent_level) {
    return .{
        .w = w,
        .wants_indent = true,
    };
}

const zig_writer = struct {
    pub const OpenOptions = struct {
        public: bool = false,
    };

    pub fn import(p: anytype, name: anytype, source: anytype) !void {
        try p.print(
            \\const @"{f}" = @import("{f}");
            \\
        , .{ asFmt(name), asFmt(source) });
    }

    pub fn openStruct(p: anytype, name: anytype, comptime opts: OpenOptions) !void {
        try openContainer(p, name, "struct", opts);
    }

    pub fn closeStruct(p: anytype) !void {
        try closeContainer(p);
    }

    pub fn openTaggedUnion(p: anytype, name: anytype, comptime opts: OpenOptions) !void {
        try openContainer(p, name, "union(enum)", opts);
    }

    pub fn closeUnion(p: anytype) !void {
        try closeContainer(p);
    }

    pub fn openStructField(p: anytype, name: anytype) !void {
        try openContainerField(p, name, "struct");
    }

    pub fn closeStructField(p: anytype) !void {
        try closeContainerField(p);
    }

    pub fn openTaggedUnionField(p: anytype, name: anytype) !void {
        try openContainerField(p, name, "union(enum)");
    }

    pub fn closeUnionField(p: anytype) !void {
        try closeContainerField(p);
    }

    pub fn emptyStruct(p: anytype, name: anytype, comptime opts: OpenOptions) !void {
        try p.print(
            \\{s}const @"{f}" = struct {{}};
            \\
        , .{ pubString(opts), asFmt(name) });
    }

    pub fn field(p: anytype, name: anytype, typ: anytype) !void {
        try p.print(
            \\@"{f}": {f},
            \\
        , .{ asFmt(name), asFmt(typ) });
    }

    fn openContainerField(p: anytype, name: anytype, typ: []const u8) !void {
        try p.print(
            \\@"{f}": {s} {{
            \\
        , .{ asFmt(name), typ });
    }

    fn openContainer(p: anytype, name: anytype, typ: []const u8, comptime opts: OpenOptions) !void {
        try p.print(
            \\{s}const @"{f}" = {s} {{
            \\
        , .{ pubString(opts), asFmt(name), typ });
    }

    fn closeContainerField(p: anytype) !void {
        try p.writeAll(
            \\},
            \\
        );
    }

    fn closeContainer(p: anytype) !void {
        try p.writeAll(
            \\};
            \\
        );
    }

    const StringFormatter = struct {
        val: []const u8,

        pub fn format(self: StringFormatter, w: *std.Io.Writer) !void {
            try w.writeAll(self.val);
        }
    };

    fn isString(comptime T: type) bool {
        const ti = @typeInfo(T);
        switch (ti) {
            .pointer => |pi| {
                const ci = @typeInfo(pi.child);
                switch (ci) {
                    .array => |ai| return ai.child == u8,
                    else => if (pi.child != u8) return false,
                }

                switch (pi.size) {
                    .c, .one, .many => return false,
                    .slice => return true,
                }
            },
            else => return false,
        }
    }

    fn AsFmt(comptime T: type) type {
        if (isString(T)) {
            return StringFormatter;
        } else if (@hasDecl(T, "format")) {
            return T;
        }

        @compileError("Unsupported type " ++ @typeName(T));
    }

    fn asFmt(val: anytype) AsFmt(@TypeOf(val)) {
        switch (AsFmt(@TypeOf(val))) {
            StringFormatter => return StringFormatter{ .val = val },
            else => return val,
        }
    }

    fn pubString(comptime opts: OpenOptions) []const u8 {
        return if (opts.public) "pub " else "";
    }
};

const zw = zig_writer;

fn genInterfaceProperty(prop: *DbusSchemaParser.Property, p: anytype) !void {
    try zw.field(p, prop.name, helpers.dbusToZigType(prop.typ));
}

fn genInterfaceMethod(method: *DbusSchemaParser.Method, p: anytype) !void {
    if (method.args.len == 0) {
        try zw.field(p, method.name, "void");
        return;
    }

    try zw.openStructField(p, method.name);

    var args_it = method.args.iter();

    const field_printer = p.indent();
    while (args_it.next()) |arg| {
        try zw.field(field_printer, arg.name, helpers.dbusToZigType(arg.typ));
    }

    try zw.closeStructField(p);
}

fn genDocstring(reader: *std.fs.File.Reader, interface: *DbusSchemaParser.Interface, p: anytype) !void {
    try reader.seekTo(interface.xml_start);

    try reader.seekTo(interface.xml_start);

    const xml_len = interface.xml_end - interface.xml_start;

    var line_buf: [4096]u8 = undefined;
    var limited = reader.interface.limited(.limited(xml_len), &line_buf);

    // zig_writer is not generic enough to do everything, we just write this
    // part ourselves

    try p.writeAll(
        \\
        \\pub const docstring: []const u8 =
        \\
    );

    while (try limited.interface.takeDelimiter('\n')) |line| {
        try p.print(
            \\    \\{s}
            \\
        , .{line});
    }

    try p.writeAll(
        \\    ;
        \\
    );
}

fn genInterfaceMethods(p: anytype, interface: *DbusSchemaParser.Interface) !void {
    try zw.openTaggedUnionField(p, "method");

    var method_it = interface.methods.iter();

    const fp = p.indent();
    while (method_it.next()) |method| {
        try genInterfaceMethod(method, fp);
    }

    try zw.closeUnionField(p);
}

fn genInterfacePropertyType(interface: *DbusSchemaParser.Interface, p: anytype) !void {
    const opts = zw.OpenOptions{ .public = true };

    if (interface.properties.len == 0) {
        try zw.emptyStruct(p, "Property", opts);
        return;
    }

    try zw.openTaggedUnion(p, "Property", .{ .public = true });
    var property_it = interface.properties.iter();
    while (property_it.next()) |prop| {
        try zw.field(p.indent(), prop.name, helpers.dbusToZigType(prop.typ));
    }

    try zw.closeUnion(p);
}

fn genInterface(reader: *std.fs.File.Reader, interface: *DbusSchemaParser.Interface, p: anytype) !void {
    try zw.openTaggedUnionField(p, interface.name);

    const interface_p = p.indent();

    try genInterfaceMethods(interface_p, interface);
    try zw.field(interface_p, "get_property", "Property");
    try zw.field(interface_p, "set_property", "Property");

    try interface_p.writeAll("\n");

    try genInterfacePropertyType(interface, interface_p);

    try genDocstring(reader, interface, interface_p);

    try zw.closeUnionField(p);
}

fn resolveFullPath(base_path: []const u8, interface_path: []const u8, out_buf: []u8) ![]const u8 {
    return try std.fmt.bufPrint(
        out_buf,
        "{f}",
        .{
            std.fs.path.fmtJoin(&.{ base_path, interface_path }),
        },
    );
}

fn genInterfaces(alloc: sphtud.alloc.LinearAllocator, interface_path: []const u8, p: anytype) !void {
    const cp = alloc.checkpoint();
    defer alloc.restore(cp);

    const interface_f = try std.fs.cwd().openFile(interface_path, .{});
    defer interface_f.close();

    var reader_buf: [4096]u8 = undefined;
    var reader = interface_f.reader(&reader_buf);

    var xmlr = sphtud.xml.Parser.init(&reader.interface);
    var schema_parser = try DbusSchemaParser.init(alloc.allocator(), alloc.expansion());

    var content_writer = std.Io.Writer.Discarding.init(&.{});
    while (try xmlr.next(&content_writer.writer)) |item| {
        try schema_parser.step(item);
    }

    var interfaces = schema_parser.output.iter();
    while (interfaces.next()) |interface| {
        try genInterface(&reader, interface, p);
    }
}

pub fn main() !void {
    var alloc_buf: [1 * 1024 * 1024]u8 = undefined;
    var alloc = sphtud.alloc.BufAllocator.init(&alloc_buf);

    var args = std.process.args();

    // process name
    _ = args.next();

    const service_def_path = args.next() orelse return error.NoServiceDef;
    const output_path = args.next() orelse return error.NoOutPath;
    const deps_path = args.next() orelse return error.NoDeps;

    const service_def_file = try std.fs.cwd().openFile(service_def_path, .{});
    defer service_def_file.close();

    const base_path = std.fs.path.dirname(service_def_path).?;
    var service_def_reader_buf: [4096]u8 = undefined;
    var service_f_reader = service_def_file.reader(&service_def_reader_buf);

    var output_file = try std.fs.cwd().createFile(output_path, .{});
    var output_buf: [4096]u8 = undefined;
    var output_writer = output_file.writer(&output_buf);

    var deps_file = try std.fs.cwd().createFile(deps_path, .{});
    var deps_buf: [4096]u8 = undefined;
    var deps_writer = deps_file.writer(&deps_buf);

    try deps_writer.interface.print("{s}: ", .{output_path});

    const w = &output_writer.interface;

    var p = indentPrinter(w, 0);
    try zw.import(&p, "dbus", "sphdbus");
    try p.writeAll("\n");

    try zw.openTaggedUnion(&p, "Request", .{ .public = true });

    var service_parser = sphtud.xml.Parser.init(&service_f_reader.interface);
    var discarding_w = std.Io.Writer.Discarding.init(&.{});
    while (try service_parser.next(&discarding_w.writer)) |item| switch (item.type) {
        .element_start => {
            const object_path = try item.attributeByKey("name");
            const interface = try item.attributeByKey("interface");

            const fp = p.indent();
            try zw.openTaggedUnionField(fp, object_path.?);

            var full_path_buf: [std.fs.max_path_bytes]u8 = undefined;
            const full_interface_path = try resolveFullPath(base_path, interface.?, &full_path_buf);
            try deps_writer.interface.print("{s} ", .{full_interface_path});

            try genInterfaces(alloc.linear(), full_interface_path, fp.indent());

            try zw.closeUnionField(fp);
        },
        else => {},
    };

    try zw.closeUnion(&p);

    try output_writer.interface.flush();
    try deps_writer.interface.flush();
}
