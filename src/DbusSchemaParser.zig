const std = @import("std");
const sphtud = @import("sphtud");

const DbusSchemaParser = @This();

alloc: std.mem.Allocator,
expansion_alloc: sphtud.util.ExpansionAlloc,
current_interface: Interface = .{},
current_method: Method = .{},
output: sphtud.util.RuntimeSegmentedList(Interface),
state: enum {
    default,
    interface,
    method,
} = .default,

pub fn init(alloc: std.mem.Allocator, expansion_alloc: sphtud.util.ExpansionAlloc) !DbusSchemaParser {
    return .{
        .alloc = alloc,
        .expansion_alloc = expansion_alloc,
        .output = try .init(
            alloc,
            expansion_alloc,
            // FIXME: Sane guesses please :)
            100,
            1000,
        ),
    };
}

pub fn step(self: *DbusSchemaParser, item: sphtud.xml.Item) !void {
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
                    self.expansion_alloc,
                    (try item.attributeByKey("name")) orelse return error.NoInterfaceName,
                    item.stream_start,
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
                    self.expansion_alloc,
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
                self.current_interface.xml_end = item.stream_end;
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

pub const MethodArg = struct {
    typ: []const u8,
    name: []const u8,
};

pub const Method = struct {
    name: []const u8 = "",
    args: sphtud.util.RuntimeSegmentedList(MethodArg) = .empty,
    ret: sphtud.util.RuntimeSegmentedList(MethodArg) = .empty,

    pub fn init(alloc: std.mem.Allocator, expansion_alloc: sphtud.util.ExpansionAlloc, name: []const u8) !Method {
        return .{
            .name = try alloc.dupe(u8, name),
            // FIXME: Update guesses
            .args = try .init(alloc, expansion_alloc, 100, 1000),
            // FIXME: Update guesses
            .ret = try .init(alloc, expansion_alloc, 100, 1000),
        };
    }
};

pub const Interface = struct {
    name: []const u8 = "",
    methods: sphtud.util.RuntimeSegmentedList(Method) = .empty,
    properties: sphtud.util.RuntimeSegmentedList(Property) = .empty,

    xml_start: usize = 0,
    xml_end: usize = 0,

    pub fn init(alloc: std.mem.Allocator, expansion_alloc: sphtud.util.ExpansionAlloc, name: []const u8, xml_start: usize) !Interface {
        return .{
            .name = try alloc.dupe(u8, name),
            .xml_start = xml_start,
            .xml_end = xml_start,
            // FIXME: update guesses,
            .methods = try .init(alloc, expansion_alloc, 100, 10000),
            .properties = try .init(alloc, expansion_alloc, 100, 10000),
        };
    }
};

pub const Property = struct {
    name: []const u8 = "",
    typ: []const u8 = "",
    access: PropertyAccess = .read,

    const PropertyAccess = enum {
        read,
        readwrite,
    };
};
