const std = @import("std");
const sphtud = if (builtin.is_test) @import("sphtud") else void;
const builtin = @import("builtin");

pub fn sessionBus() !std.net.Stream {
    const session_address = std.posix.getenv("DBUS_SESSION_BUS_ADDRESS") orelse return error.NoSessionAddress;
    const socket_path = try extractUnixPathFromAddress(session_address);
    return try std.net.connectUnixSocket(socket_path);
}

fn extractUnixPathFromAddress(address: []const u8) ![]const u8 {
    const tag = "unix:path=";
    if (!std.mem.startsWith(u8, address, tag)) return error.NotUnixPath;
    return address[tag.len..];
}

fn waitForStartsWith(reader: *std.Io.Reader, start: []const u8, err: anyerror) !void {
    const response = try reader.takeDelimiterInclusive('\n');
    if (!std.mem.startsWith(u8, response, start)) {
        std.log.err("{s} is not {s}\n", .{ response, start });
        return err;
    }
}

pub const SignatureTokenizer = struct {
    reader: *std.Io.Reader,

    pub const Token = enum {
        array_start,
        struct_start,
        struct_end,
        kv_start,
        kv_end,
        u32,
        u64,
        i32,
        i64,
        f64,
        object,
        string,
        bool,
        variant,
    };

    pub fn next(self: SignatureTokenizer) !?Token {
        const ret = (try self.peek()) orelse return null;
        self.reader.toss(1);
        return ret;
    }

    pub fn peek(self: SignatureTokenizer) !?Token {
        const b = (try self.peekByte()) orelse return null;

        return switch (b) {
            'a' => .array_start,
            '(' => .struct_start,
            ')' => .struct_end,
            '{' => .kv_start,
            '}' => .kv_end,
            'u' => .u32,
            'i' => .i32,
            't' => .u64,
            'o' => .object,
            's' => .string,
            'b' => .bool,
            'x' => .i64,
            'v' => .variant,
            'd' => .f64,
            else => {
                std.log.err("Unhandled type {c}", .{b});
                return error.UnhandledSignature;
            },
        };

    }

    fn peekByte(self: SignatureTokenizer) !?u8 {
        return self.reader.peekByte() catch |e| {
            switch (e) {
                error.EndOfStream => return null,
                else => return e,
            }
        };
    }
};

pub const DbusEndianness = enum(u8) {
    little = 'l',
    big = 'b',

    fn toBuiltin(self: DbusEndianness) std.builtin.Endian {
        return switch (self) {
            .little => return .little,
            .big => return .big,
        };
    }
};

const MsgType = enum(u8) {
    invalid = 0,
    call = 1,
    ret = 2,
    err = 3,
    signal = 4,
};

const DBusVersion = enum(u8) {
    @"1" = 1,
};

const HeaderField = enum(u8) {
    path = 1,
    interface = 2,
    member = 3,
    reply_serial = 5,
    destination = 6,
    sender = 7,
    signature = 8,
};

const DbusMessageWriter = struct {
    pos: u32,
    writer: *std.Io.Writer,

    fn writeByte(self: *DbusMessageWriter, b: u8) !void {
        try self.writer.writeByte(b);
        self.pos += 1;
    }

    fn writeU32(self: *DbusMessageWriter, val: u32) !void {
        try self.alignForwards(4);
        try self.writer.writeInt(u32, val, builtin.cpu.arch.endian());
        self.pos += 4;
    }

    fn writeF64(self: *DbusMessageWriter, val: f64) !void {
        try self.writeI64(@bitCast(val));
    }

    fn writeI64(self: *DbusMessageWriter, val: i64) !void {
        try self.alignForwards(8);
        try self.writer.writeInt(i64, val, builtin.cpu.arch.endian());
        self.pos += 8;
    }

    fn writeAll(self: *DbusMessageWriter, data: []const u8) !void {
        const len_u32 = std.math.cast(u32, data.len) orelse return error.InvalidLen;
        try self.writer.writeAll(data);
        self.pos += len_u32;
    }

    fn writeVariantTag(self: *DbusMessageWriter, tag: []const u8) !void {
        const tag_len_u8 = std.math.cast(u8, tag.len) orelse return error.InvalidLen;
        try self.writer.writeByte(tag_len_u8);
        self.pos += 1;

        try self.writer.writeAll(tag);
        self.pos += tag_len_u8;

        try self.writer.writeByte(0);
        self.pos += 1;
    }

    fn writeVariant(self: *DbusMessageWriter, val: Variant) !void {
        const tag = try val.tag();
        try self.writeVariantTag(tag);
        switch (val) {
            .string, .object => |v| try self.writeStringLike(v),
            .signature => |v| {
                try self.writeByte(@intCast(v.len));
                try self.writeAll(v);
                try self.writeByte(0);
            },
            .f64 => |v| try self.writeF64(v),
            .u32 => |v| try self.writeU32(v),
            else => {
                std.log.err("Unhandled variant: {t}", .{val});
                return error.Unimplemented;
            },
        }
    }

    fn writeStringLike(self: *DbusMessageWriter, s: []const u8) !void {
        const s_len_u32 = std.math.cast(u32, s.len) orelse return error.InvalidLen;
        try self.writeU32(s_len_u32);

        try self.writer.writeAll(s);
        self.pos += s_len_u32;

        try self.writer.writeByte(0);
        self.pos += 1;
    }

    fn alignForwards(self: *DbusMessageWriter, alignment: u32) !void {
        const new_pos = std.mem.alignForward(u32, self.pos, alignment);
        try self.writer.splatByteAll(0, new_pos - self.pos);
        self.pos = new_pos;
    }
};

const DbusMessageReader = struct {
    // FIXME: Pos shouldn't be needed if reader is known to be fixed, which I think it is...
    pos: u32,
    reader: *std.Io.Reader,

    fn toss(self: *DbusMessageReader, amount: u32) void {
        self.pos += amount;
        self.reader.toss(amount);
    }

    fn readByte(self: *DbusMessageReader) !u8 {
        const ret = try self.reader.takeByte();
        self.pos += 1;
        return ret;
    }

    fn readBytes(self: *DbusMessageReader, n: u32) ![]const u8 {
        const ret = try self.reader.take(n);
        self.pos += n;
        return ret;
    }

    fn readU32(self: *DbusMessageReader, endianness: DbusEndianness) !u32 {
        try self.alignForwards(4);
        const ret = try self.reader.takeInt(u32, endianness.toBuiltin());
        self.pos += 4;
        return ret;
    }

    fn readI32(self: *DbusMessageReader, endianness: DbusEndianness) !i32 {
        return @bitCast(try self.readU32(endianness));
    }

    fn readU64(self: *DbusMessageReader, endianness: DbusEndianness) !u64 {
        try self.alignForwards(8);
        const ret = try self.reader.takeInt(u64, endianness.toBuiltin());
        self.pos += 8;
        return ret;
    }

    fn readF64(self: *DbusMessageReader, endianness: DbusEndianness) !f64 {
        return @bitCast(try self.readU64(endianness));
    }

    fn readI64(self: *DbusMessageReader, endianness: DbusEndianness) !i64 {
        return @bitCast(try self.readU64(endianness));
    }

    fn alignForwards(self: *DbusMessageReader, alignment: u32) !void {
        const new_pos = std.mem.alignForward(u32, self.pos, alignment);
        try self.reader.discardAll(new_pos - self.pos);
        self.pos = new_pos;
    }

    fn dupeIfAlloc(alloc: ?std.mem.Allocator, comptime T: type, val: []const T) ![]const T {
        const a = alloc orelse return val;
        return try a.dupe(T, val);
    }

    fn readSignature(self: *DbusMessageReader) ![]const u8 {
        const signature_len = try self.readByte();
        return (try self.readBytes(signature_len + 1))[0..signature_len];
    }

    fn readStringLike(self: *DbusMessageReader, endianness: DbusEndianness) ![]const u8 {
        const len = try self.readU32(endianness);
        return (try self.readBytes(len + 1))[0..len];
    }

    fn readVariant(self: *DbusMessageReader, endianness: DbusEndianness) !Variant {
        std.debug.assert(self.reader.vtable == std.Io.Reader.fixed(&.{}).vtable);

        const signature = try parseSignature(try self.readSignature());

        switch (signature) {
            .empty => {
                return error.Unimplemented;
            },
            .byte => {
                return .{ .byte = try self.readByte() };
            },
            .bool => {
                return .{ .bool = try self.readU32(endianness) > 0 };
            },
            .string => {
                const s = try self.readStringLike(endianness);
                return Variant{ .string = s };
            },
            .object => {
                const s = try self.readStringLike(endianness);
                return Variant{ .object = s };
            },
            .signature => {
                const s = try self.readSignature();
                return Variant{ .signature = s };
            },
            .u32 => {
                const val = try self.readU32(endianness);
                return .{ .u32 = val };
            },
            .i64 => {
                const val = try self.readI64(endianness);
                return .{ .i64 = val };
            },
            .f64 => {
                const val = try self.readF64(endianness);
                return .{ .f64 = val };
            },
            .unknown => {
                return .unknown;
            },
        }
    }

    fn readVariant2(self: *DbusMessageReader, endianness: DbusEndianness) !Variant2 {
        std.debug.assert(self.reader.vtable == std.Io.Reader.fixed(&.{}).vtable);

        // FIXME: I think struct alignment won't work if this isn't true, but
        // unsure, we should check
        //std.debug.assert(self.pos % 8 == 0);

        // Skip signature len
        const data_start = self.reader.seek;

        const signature_s = try self.readSignature();
        var signature_reader = std.Io.Reader.fixed(signature_s);
        var signature_it = SignatureTokenizer {
            .reader = &signature_reader,
        };

        const Tag = enum {
            array,
            @"struct",
        };
        var tag_stack_buf: [10]Tag = undefined;
        var tag_stack = std.ArrayList(Tag).initBuffer(&tag_stack_buf);

        while (try signature_it.next()) |token| {
            const in_array = blk: {
                for (tag_stack.items) |t| {
                    if (t == .array) break :blk true;
                }
                break :blk false;
            };
            // FIXME: This feels like it might already exist
            switch (token) {
                .array_start => {
                    // Array length in bytes, then data
                    if (!in_array) {
                        const len_bytes = try self.readU32(endianness);
                        const cp = signature_it.reader.seek;
                        const next_token = try signature_it.next() orelse return error.InvalidArraySignature;
                        // FIXME: HACK HACK HACK
                        signature_it.reader.seek = cp;
                        switch (next_token) {
                            .u64, .f64, .i64, .kv_start, .struct_start => try self.alignForwards(8),
                            .array_start, .bool, .u32, .i32, .string, .object => try self.alignForwards(4),
                            .kv_end, .struct_end => return error.InvalidArraySignature,
                            .variant => {},

                        }
                        self.toss(len_bytes);
                    }
                    try tag_stack.appendBounded(.array);
                },
                .kv_start, .struct_start => {
                    if (!in_array) {
                        try self.alignForwards(8);
                    }
                    try tag_stack.appendBounded(.@"struct");
                },
                .struct_end, .kv_end => {
                    const last_tag = tag_stack.pop();
                    std.debug.assert(last_tag == .@"struct");
                },
                .bool, .u32, .i32, => {
                    if (!in_array) {
                        _ = try self.readU32(endianness);
                    }
                },
                .u64, .i64, .f64 => {
                    if (!in_array) {
                        _ = try self.readI64(endianness);
                    }
                },
                .object, .string => {
                    if (!in_array) {
                        _ = try self.readStringLike(endianness);
                    }
                },
                .variant => {
                    if (!in_array) {
                        _ = try self.readVariant2(endianness);
                    }
                },
            }

            switch (token) {
                .struct_end, .kv_end,
                .bool, .u32, .i32,
                .u64, .i64, .f64,
                .object, .string,
                .variant => {
                    if (tag_stack.getLastOrNull()) |t| {
                        if (t == .array) {
                            _ = tag_stack.pop();
                        }
                    }
                },
                .struct_start, .kv_start, .array_start => {},
            }
        }

        return .{
            .signature_len = @intCast(signature_s.len),
            .variant_start = @intCast(data_start),
            .data = self.reader.buffer[0..self.reader.seek],
        };
    }
};

const SignatureTag = enum {
    empty,
    byte,
    string,
    object,
    bool,
    signature,
    u32,
    i64,
    f64,
    unknown,

    pub fn tag(self: SignatureTag) ![]const u8 {
        return switch (self) {
            .empty => "",
            .byte => "y",
            .string => "s",
            .object => "o",
            .bool => "b",
            .signature => "g",
            .u32 => "u",
            .i64 => "x",
            .f64 => "d",
            .unknown => return error.UnknownTag,
        };
    }
};

pub const Variant2 = struct {
    signature_len: u32,
    variant_start: u32,
    data: []const u8,

    pub fn signature(self: Variant2) []const u8 {
        return self.data[self.variant_start + 1..self.variant_start + self.signature_len + 1];
    }

    pub fn toConcrete(self: Variant2, comptime T: type, endianness: DbusEndianness) !T {

        if (!std.mem.eql(u8, generateDbusSignature(T), self.data[self.variant_start + 1..self.variant_start + self.signature_len + 1])) {
            return error.InvalidSignature;
        }

        var io_reader = std.Io.Reader.fixed(self.data);
        var dr = DbusMessageReader {
            .pos = 0,
            .reader = &io_reader,
        };
        dr.toss(self.variant_start + self.signature_len);

        return dbusParseBodyInner(T, endianness, &dr);
    }

    pub fn fromConcrete(v: anytype) !Variant2 {
        _ = v;
        unreachable;
    }
};

pub const Variant = union(SignatureTag) {
    empty,
    byte: u8,
    string: []const u8,
    object: []const u8,
    bool: bool,
    signature: []const u8,
    u32: u32,
    i64: i64,
    f64: f64,
    unknown,

    pub fn eql(self: Variant, other: Variant) bool {
        const self_tag: SignatureTag = self;
        const other_tag: SignatureTag = other;
        if (self_tag != other_tag) return false;


        switch (self_tag) {
            .byte => return self.byte == other.byte,
            .string => return std.mem.eql(u8, self.string, other.string),
            .object => return std.mem.eql(u8, self.object, other.object),
            .bool => return self.bool == other.bool,
            .signature => return std.mem.eql(u8, self.signature, other.signature),
            .u32 => return self.u32 == other.u32,
            .i64 => return self.i64 == other.i64,
            .f64 => return self.f64 == other.f64,
            else => unreachable,
        }
    }

    pub fn toConcrete(self: Variant, comptime T: type) !T {
        switch (T) {
            u8 => switch (self) {
                .byte => |v| return v,
                else => return error.IncorrectType,
            },
            DbusString => switch (self) {
                .string => |v| return .{ .inner = v },
                else => return error.IncorrectType,
            },
            DbusObject => switch (self) {
                .object => |v| return .{ .inner = v },
                else => return error.IncorrectType,
            },
            u32 => switch (self) {
                .u32 => |v| return v,
                else => return error.IncorrectType,
            },
            i64 => switch (self) {
                .i64 => |v| return v,
                else => return error.IncorrectType,
            },
            f64 => switch (self) {
                .f64 => |v| return v,
                else => return error.IncorrectType,
            },

            else => return error.UnhandledType,
        }
    }

    pub fn fromConcrete(v: anytype) !Variant {
        switch (@TypeOf(v)) {
            u8 => return .{ .byte = v },
            DbusString => return .{ .string = v.inner },
            DbusObject => return .{ .object = v.inner },
            u32 => return .{ .u32 = v },
            i64 => return .{ .i64 = v },
            f64 => return .{ .f64 = v },
            else => return error.UnhandledType,
        }
    }

    pub fn tag(self: Variant) ![]const u8 {
        return SignatureTag.tag(self);
    }

    pub fn format(self: Variant, writer: *std.Io.Writer) !void {
        switch (self) {
            .empty => {},
            .byte => |v| try writer.print("{d}", .{v}),
            .string => |v| try writer.print("{s}", .{v}),
            .bool => |v| try writer.print("{}", .{v}),
            .object => |v| try writer.print("{s}", .{v}),
            .signature => |v| try writer.print("{s}", .{v}),
            .u32 => |v| try writer.print("{d}", .{v}),
            .i64 => |v| try writer.print("{d}", .{v}),
            .f64 => |v| try writer.print("{d}", .{v}),
            .unknown => try writer.print("unknown", .{}),
        }
    }
};

fn parseSignature(sig: []const u8) !SignatureTag {
    if (std.mem.eql(u8, "s", sig)) return .string;
    if (std.mem.eql(u8, "u", sig)) return .u32;
    if (std.mem.eql(u8, "g", sig)) return .signature;
    if (std.mem.eql(u8, "b", sig)) return .bool;
    if (std.mem.eql(u8, "o", sig)) return .object;
    if (std.mem.eql(u8, "", sig)) return .empty;
    if (std.mem.eql(u8, "x", sig)) return .i64;
    if (std.mem.eql(u8, "d", sig)) return .f64;
    std.log.err("Unimplemented signature: {s} (len {d})", .{ sig, sig.len });
    return .unknown;
}

const HeaderFieldKV = struct {
    typ: HeaderField,
    val: Variant,
};

const HeaderIt = struct {
    endianness: DbusEndianness,
    fixed_reader: std.Io.Reader,

    fn next(self: *HeaderIt) !?HeaderFieldKV {
        std.debug.assert(self.fixed_reader.vtable == std.Io.Reader.fixed(&.{}).vtable);

        if (self.fixed_reader.seek == self.fixed_reader.buffer.len) {
            return null;
        }

        var dbus_reader = DbusMessageReader {
            .pos = @intCast(self.fixed_reader.seek),
            .reader = &self.fixed_reader,
        };

        try dbus_reader.alignForwards(8);
        const header_field_byte = try dbus_reader.readByte();
        const header_field = std.meta.intToEnum(HeaderField, header_field_byte) catch return error.InvalidHeaderField;

        const val = try dbus_reader.readVariant(self.endianness);

        return .{
            .typ = header_field,
            .val = val,
        };
    }
};

pub const ParsedMessage = struct {
    endianness: DbusEndianness,
    message_type: MsgType,
    flags: u8,
    major_version: DBusVersion,
    serial: u32,
    header_buf: []const u8,
    body: []const u8,
    bytes_consumed: usize,

    pub fn parse(buf: []const u8) !ParsedMessage {
        var io_reader = std.Io.Reader.fixed(buf);
        var dbus_reader = DbusMessageReader{
            .pos = 0,
            .reader = &io_reader,
        };

        const endianness = try std.meta.intToEnum(DbusEndianness, try dbus_reader.readByte());
        const message_type = try std.meta.intToEnum(MsgType, try dbus_reader.readByte());
        const flags = try dbus_reader.readByte();
        const major_version = try std.meta.intToEnum(DBusVersion, try dbus_reader.readByte());
        const body_len = try dbus_reader.readU32(endianness);
        const serial = try dbus_reader.readU32(endianness);

        const header_field_len = try dbus_reader.readU32(endianness);

        const end_header_pos = dbus_reader.pos + header_field_len;
        try dbus_reader.alignForwards(8);

        const header_buf = buf[dbus_reader.pos..end_header_pos];

        var header_it = HeaderIt {
            .fixed_reader = std.Io.Reader.fixed(header_buf),
            .endianness = endianness,
        };

        var body_signature: []const u8 = "";

        while (try header_it.next()) |header| {
            if (header.typ == .signature) {
                if (header.val != .signature) {
                    return error.InvalidSignature;
                }
                body_signature = header.val.signature;
            }
        }

        dbus_reader.toss(header_field_len);

        if (dbus_reader.pos != end_header_pos) return error.InvalidHeader;
        try dbus_reader.alignForwards(8);

        const body = buf[dbus_reader.pos..][0..body_len];

        return .{
            .endianness = endianness,
            .message_type = message_type,
            .flags = flags,
            .major_version = major_version,
            .serial = serial,
            .header_buf = header_buf,
            .body = body,
            .bytes_consumed = dbus_reader.pos + body_len,
        };
    }

    pub fn headerIt(self: *const ParsedMessage) HeaderIt {
        return .{
            .endianness = self.endianness,
            .fixed_reader = std.Io.Reader.fixed(self.header_buf),
        };
    }

    pub fn getHeader(self: ParsedMessage, header: HeaderField) !?Variant {
        var it = self.headerIt();
        while (try it.next()) |f| {
            if (f.typ == header) {
                return f.val;
            }
        }

        return null;
    }

    pub fn signature(self: ParsedMessage) ![]const u8 {
        const s = try self.getHeader(.signature) orelse return "";
        switch (s) {
            .signature => |v| return v,
            else => return error.InvaliHeader,
        }
    }
};

pub const DbusHeader = struct {
    endianness: DbusEndianness,
    message_type: MsgType,
    flags: u8,
    major_version: DBusVersion,
    body_len: u32,
    serial: u32,
    header_fields: []const HeaderFieldKV,

    pub fn call(serial: u32, path: []const u8, destination: []const u8, interface: []const u8, member: []const u8, body: anytype, field_buf: []HeaderFieldKV) !DbusHeader {
        var header_fields = std.ArrayList(HeaderFieldKV).initBuffer(field_buf);
        try header_fields.appendSliceBounded(&.{
            .{
                .typ = .path,
                .val = .{ .object = path },
            },
            .{
                .typ = .destination,
                .val = .{ .string = destination },
            },
            .{
                .typ = .interface,
                .val = .{ .string = interface },
            },
            .{
                .typ = .member,
                .val = .{ .string = member },
            },
        });

        const body_signature = generateDbusSignature(@TypeOf(body));

        if (body_signature.len > 0) {
            try header_fields.appendBounded(.{
                .typ = .signature,
                .val = .{
                    .signature = body_signature,
                },
            });
        }

        var discarding_writer = std.Io.Writer.Discarding.init(&.{});
        try dbusSerialize(&discarding_writer.writer, body);

        return DbusHeader{
            .endianness = .little,
            .message_type = .call,
            .flags = 0,
            .major_version = .@"1",
            .body_len = @intCast(discarding_writer.fullCount()),
            .serial = serial,
            .header_fields = header_fields.items,
        };
    }

    pub fn ret(serial: u32, reply_serial: u32, destination: []const u8, body: anytype, field_buf: []HeaderFieldKV) !DbusHeader {

        var header_fields = std.ArrayList(HeaderFieldKV).initBuffer(field_buf);
        try header_fields.appendSliceBounded(&.{
            .{
                .typ = .destination,
                .val = .{ .string = destination },
            },
            .{
                .typ = .reply_serial,
                .val = .{ .u32 = reply_serial },
            },
        });

        const body_signature = generateDbusSignature(@TypeOf(body));

        if (body_signature.len > 0) {
            try header_fields.appendBounded(.{
                .typ = .signature,
                .val = .{
                    .signature = body_signature,
                },
            });
        }

        var discarding_writer = std.Io.Writer.Discarding.init(&.{});
        try dbusSerialize(&discarding_writer.writer, body);

        return DbusHeader{
            .endianness = .little,
            .message_type = .ret,
            .flags = 0,
            .major_version = .@"1",
            .body_len = @intCast(discarding_writer.fullCount()),
            .serial = serial,
            .header_fields = header_fields.items,
        };
    }

    fn serialize(self: DbusHeader, io_writer: *std.Io.Writer, body: anytype) !void {
        // We don't handle this below I don't think
        std.debug.assert(self.endianness == .little);

        var w = DbusMessageWriter{
            .pos = 0,
            .writer = io_writer,
        };

        try w.writeByte(@intFromEnum(self.endianness));
        try w.writeByte(@intFromEnum(self.message_type));
        try w.writeByte(self.flags); // flags
        try w.writeByte(@intFromEnum(self.major_version));

        try w.writeU32(self.body_len); // len
        try w.writeU32(self.serial); // serial

        var header_buf: [4096]u8 = undefined;
        var header_field_io = std.Io.Writer.fixed(&header_buf);
        var header_field_writer = DbusMessageWriter{
            .pos = w.pos + 4,
            .writer = &header_field_io,
        };

        for (self.header_fields) |header_field| {
            try header_field_writer.alignForwards(8); // struct alignment
            try header_field_writer.writeByte(@intFromEnum(header_field.typ));
            try header_field_writer.writeVariant(header_field.val);
        }

        try w.writeU32(header_field_writer.pos - w.pos - 4); // num headers
        try w.writeAll(header_field_writer.writer.buffered());

        try w.alignForwards(8); // body alignment
        try dbusSerialize(w.writer, body);
    }

    pub fn format(self: DbusHeader, w: *std.Io.Writer) !void {
        try w.print("endianness: {}\n", .{self.endianness});
        try w.print("message_type: {}\n", .{self.message_type});
        try w.print("flags: {}\n", .{self.flags});
        try w.print("major_version: {}\n", .{self.major_version});
        try w.print("body_len: {}\n", .{self.body_len});
        try w.print("serial: {}\n", .{self.serial});

        try w.print("headers\n", .{});
        for (self.header_fields) |f| {
            try w.print("    {t}: {f}\n", .{ f.typ, f.val });
        }
    }
};

fn numDigits10(val: u32) u32 {
    if (val == 0) return 0;
    return std.math.log10(val) + 1;
}

test "numDigits10" {
    try std.testing.expectEqual(3, numDigits10(999));
    try std.testing.expectEqual(4, numDigits10(1000));
    try std.testing.expectEqual(4, numDigits10(1001));
    try std.testing.expectEqual(0, numDigits10(0));
    try std.testing.expectEqual(1, numDigits10(1));
}

const AuthUidFormatter = struct {
    uid: u32,

    pub fn format(self: AuthUidFormatter, writer: *std.Io.Writer) !void {
        var divisor = std.math.pow(u32, 10, numDigits10(self.uid) - 1);
        var remaining = self.uid;

        while (divisor > 0) {
            const digit: u8 = @intCast(remaining / divisor);
            remaining = self.uid % divisor;
            try writer.writeByte('3');
            try writer.writeByte('0' + digit);
            divisor /= 10;
        }
    }
};

test "AuthUidFormatter" {
    var buf: [10]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    const formatter = AuthUidFormatter{ .uid = 1001 };
    try formatter.format(&writer);
    try std.testing.expectEqualStrings("31303031", writer.buffered());
}

pub const DbusConnectionInitializer = struct {
    state: enum {
        wait_for_ok,
        wait_for_ack,
        complete,
    },

    pub fn init(io_writer: *std.Io.Writer) !DbusConnectionInitializer {
        try io_writer.writeByte(0);
        try io_writer.print("AUTH EXTERNAL {f}\r\n", .{AuthUidFormatter{ .uid = std.posix.getuid() }});
        try io_writer.flush();

        return .{
            .state = .wait_for_ok,
        };
    }

    fn poll(self: *DbusConnectionInitializer, io_reader: *std.Io.Reader, io_writer: *std.Io.Writer) !bool {
        sw: switch (self.state) {
            .wait_for_ok => {
                try waitForStartsWith(io_reader, "OK", error.NotOk);

                try io_writer.print("NEGOTIATE_UNIX_FD\r\n", .{});
                try io_writer.flush();

                self.state = .wait_for_ack;
                continue :sw self.state;
            },
            .wait_for_ack => {
                try waitForStartsWith(io_reader, "AGREE_UNIX_FD", error.NoUnixFd);

                try io_writer.print("BEGIN\r\n", .{});

                const hello_message = DbusHeader{
                    .endianness = .little,
                    .message_type = .call,
                    .flags = 0,
                    .major_version = .@"1",
                    .body_len = 0,
                    .serial = 1,
                    .header_fields = &.{
                        .{
                            .typ = .path,
                            .val = .{ .object = "/org/freedesktop/DBus" },
                        },
                        .{
                            .typ = .destination,
                            .val = .{ .string = "org.freedesktop.DBus" },
                        },
                        .{
                            .typ = .interface,
                            .val = .{ .string = "org.freedesktop.DBus" },
                        },
                        .{
                            .typ = .member,
                            .val = .{ .string = "Hello" },
                        },
                    },
                };
                try hello_message.serialize(io_writer, .{});
                try io_writer.flush();

                self.state = .complete;
                continue :sw self.state;
            },
            .complete => {
                return true;
            },
        }
    }
};

fn dbusSerializeInner(dbus_writer: *DbusMessageWriter, val: anytype) !void {
    switch (@TypeOf(val)) {
        DbusString, DbusObject => {
            try dbus_writer.writeStringLike(val.inner);
            return;
        },
        i64 => {
            try dbus_writer.writeI64(val);
            return;
        },
        u32 => {
            try dbus_writer.writeU32(val);
            return;
        },
        f64 => {
            try dbus_writer.writeF64(val);
            return;
        },
        // FIXME: Remove variant1
        Variant => {
            try dbus_writer.writeVariant(val);
            return;
        },
        Variant2 => {
            unreachable;
        },
        else => {},
    }

    switch (@typeInfo(@TypeOf(val))) {
        .@"struct" => |si| {
            try dbus_writer.alignForwards(8);
            inline for (si.fields) |field| {
                try dbusSerializeInner(dbus_writer, @field(val, field.name));
            }
            return;
        },
        else => {},
    }

    @compileError("Unhandled type " ++ @typeName(@TypeOf(val)));
}

fn dbusSerialize(io_writer: *std.Io.Writer, val: anytype) !void {
    var dbus_writer = DbusMessageWriter{
        .pos = 0,
        .writer = io_writer,
    };

    return dbusSerializeInner(&dbus_writer, val);
}

fn getDbusAlignment(comptime T: type) u32 {
    switch (T) {
        u32, i32, DbusObject, DbusString => return 4,
        Variant, Variant2 => return 1,
        u64, f64, i64 => return 8,
        else => {},
    }

    switch (@typeInfo(T)) {
        .@"struct" => {
            if (@hasDecl(T, "DbusArrayMarker")) return 4;
            return 8;
        },
        else => {},
    }

    @compileError("Unknown alignment for " ++ @typeName(T));
}

pub fn dbusParseBodyInner(comptime T: type, endianness: DbusEndianness, dr: *DbusMessageReader) !T {
    switch (T) {
        DbusObject, DbusString => {
            const string_len = try dr.readU32(endianness);
            // Known that string content lives in body, so it's ok
            const s = try dr.readBytes(string_len);
            _ = try dr.readBytes(1);

            return .{ .inner = s };
        },
        Variant => {
            // Known that string content lives in body, so it's ok to not pass allocator
            return try dr.readVariant(endianness);
        },
        Variant2 => {
            return try dr.readVariant2(endianness);
        },
        u32 => {
            return try dr.readU32(endianness);
        },
        i32 => {
            return try dr.readI32(endianness);
        },
        u64 => {
            return try dr.readU64(endianness);
        },
        f64 => {
            return try dr.readF64(endianness);
        },
        else => {},
    }

    switch (@typeInfo(T)) {
        .@"struct" => |si| {
            if (@hasDecl(T, "DbusArrayMarker")) {
                const array_len_bytes = try dr.readU32(endianness);
                try dr.alignForwards(getDbusAlignment(T.T));

                const start = dr.reader.seek;
                dr.toss(array_len_bytes);


                // Align forwards to inner Type alignment
                // consume array_len_bytes

                // FIXME: Actually implmement
                return .{
                    .start = @intCast(start),
                    .endianness = endianness,
                    .data = dr.reader.buffer[0..dr.reader.seek],
                };

            }
            var ret: T = undefined;
            try dr.alignForwards(8);
            inline for (si.fields) |field| {
                @field(ret, field.name) = try dbusParseBodyInner(field.type, endianness, dr);
            }
            return ret;
        },
        else => {},
    }

    @compileError("Unsupported type " ++ @typeName(T));
}

pub fn dbusParseBody(comptime T: type, message: ParsedMessage) !T {
    var reader = std.Io.Reader.fixed(message.body);

    const signature = try message.signature();
    if (!std.mem.eql(u8, signature, generateDbusSignature(T))) {
        std.log.err("Expected {s} got {s}\n", .{ generateDbusSignature(T), signature });
        return error.InvalidType;
    }

    var dr = DbusMessageReader{
        .pos = 0,
        .reader = &reader,
    };

    return dbusParseBodyInner(T, message.endianness, &dr);
}

pub fn dbusConnection(reader: *std.Io.Reader, writer: *std.Io.Writer) !DbusConnection {
    return .{
        .reader = reader,
        .writer = writer,
        .serial = 2,
        .state = .{
            .initializing = try DbusConnectionInitializer.init(writer),
        },
    };
}

pub const DbusConnection = struct {
        serial: u32,
        reader: *std.Io.Reader,
        writer: *std.Io.Writer,
        state: union(enum) {
            initializing: DbusConnectionInitializer,
            ready,
        },

        const Self = @This();

        pub fn call(self: *Self, path: []const u8, destination: []const u8, interface: []const u8, member: []const u8, body: anytype) !CallHandle {
            if (self.state != .ready) return error.Uninitialized;

            var field_buf: [6]HeaderFieldKV = undefined;
            const to_send = try DbusHeader.call(
                self.serial,
                path,
                destination,
                interface,
                member,
                body,
                &field_buf,
            );
            const handle = CallHandle { .inner = self.serial };
            // We shouldn't have an outstanding request from 2^32 requests ago
            self.serial +%= 1;

            try to_send.serialize(self.writer, body);
            try self.writer.flush();

            return handle;
        }

        pub fn ret(self: *DbusConnection, reply_serial: u32, destination: []const u8, body: anytype) !void {
            if (self.state != .ready) return error.Uninitialized;

            var field_buf: [6]HeaderFieldKV = undefined;
            const to_send = try DbusHeader.ret(
                self.serial,
                reply_serial,
                destination,
                body,
                &field_buf,
            );
            // We shouldn't have an outstanding request from 2^32 requests ago
            self.serial +%= 1;

            try to_send.serialize(self.writer, body);
            try self.writer.flush();
        }

        // FIXME: Move out of DbusConnection
        pub const CallHandle = struct { inner: u32 };

        pub const Response = union(enum) {
            initialized,
            call: ParsedMessage,
            response: struct {
                handle: CallHandle,
                header: ParsedMessage,
            },
            none,
        };

        pub fn poll(self: *Self) !Response {
            switch (self.state) {
                .initializing => |*initializer| {
                    if (!try initializer.poll(self.reader, self.writer)) {
                        return .none;
                    }
                    self.state = .ready;
                    return .initialized;
                },
                .ready => {
                    return self.pollReady();
                },
            }
        }

        fn pollReady(self: *Self) !Response {
            // It's easier to parse from a buffer than it is to write
            // DbusHeader.parse in a way where it doesn't consume bytes from
            // the reader for a partial read. Fill in outer loop as much as
            // possible, then if the parse fails below because there wasn't
            // enough data, we can just fill again until we return WouldBlock
            // here
            if (self.reader.bufferedLen() == 0) {
                try self.reader.fillMore();
            }

            while (true) {
                const message = ParsedMessage.parse(self.reader.buffered()) catch |e| switch (e) {
                    error.EndOfStream => return .none,
                    else => return e,
                };

                self.reader.toss(message.bytes_consumed);

                var reply_for: ?u32 = null;
                var header_it = message.headerIt();
                while (try header_it.next()) |f| {
                    if (f.typ == .reply_serial) {
                        if (f.val != .u32) break;
                        reply_for = f.val.u32;
                    }
                }

                if (reply_for) |rf| {
                    return .{
                        .response = .{
                            .handle = .{ .inner = rf },
                            .header = message,
                        },
                    };
                }

                if (message.message_type == .call) {
                    return .{
                        .call = message,
                    };
                }
            }
        }
};

pub const DbusObject = struct {
    inner: []const u8,
};

pub const DbusString = struct {
    inner: []const u8,
};

pub fn DbusKV(comptime Key: type, comptime Val: type) type {
    return struct {
        // For metaprogramming :)
        pub const DbusKVMarker = {};

        key: Key,
        val: Val,
    };
}

pub fn DbusArray(comptime Val: type) type {
    return struct {
        // For metaprogramming :)
        pub const DbusArrayMarker = {};
        pub const T = Val;

        start: u32,
        data: []const u8,
        endianness: DbusEndianness,

        const Iter = struct {
            offs: u32,
            data: []const u8,
            endianness: DbusEndianness,

            pub fn next(self: *Iter) !?T {
                if (self.offs >= self.data.len) return null;

                var io_reader = std.Io.Reader.fixed(self.data);
                var reader = DbusMessageReader {
                    .pos = 0,
                    .reader = &io_reader,
                };
                reader.toss(self.offs);

                const ret = try dbusParseBodyInner(T, self.endianness, &reader);
                self.offs = @intCast(io_reader.seek);
                return ret;
            }
        };

        pub fn iter(self: @This()) Iter {
            return .{
                .offs = self.start,
                .data = self.data,
                .endianness = self.endianness,
            };
        }
    };
}

fn generateDbusSignatureInner(comptime T: type, depth: usize) []const u8 {
    switch (T) {
        DbusString => return "s",
        DbusObject => return "o",
        i64 => return "x",
        u32 => return "u",
        i32 => return "i",
        u64 => return "t",
        Variant => return "v",
        Variant2 => return "v",
        f64 => return "d",
        else => {},
    }

    switch (@typeInfo(T)) {
        .@"struct" => |si| {
            if (@hasDecl(T, "DbusArrayMarker")) {
                return "a" ++ generateDbusSignatureInner(T.T, depth + 1);
            }
            const struct_open = if (@hasDecl(T, "DbusKVMarker")) "{" else "(";
            const struct_close = if (@hasDecl(T, "DbusKVMarker")) "}" else ")";

            var ret: []const u8 = if (depth == 0) "" else struct_open;
            for (si.fields) |field| {
                ret = ret ++ generateDbusSignatureInner(field.type, depth + 1);
            }
            if (depth == 0) {
                return ret;
            } else {
                return ret ++ struct_close;
            }
        },
        else => {},
    }

    @compileError("unimplemented for field type " ++ @typeName(T));
}

pub fn generateDbusSignature(comptime T: type) []const u8 {
    return comptime blk: {
        break :blk generateDbusSignatureInner(T, 0);
    };
}

test "dbus flat sig gen" {
    const s = generateDbusSignature(struct {
        x: DbusString,
        y: DbusObject,
        i: i64,
        u: u32,
    });

    try std.testing.expectEqualStrings("soxu", s);
}

test "dbus array sig gen" {
    const s = generateDbusSignature([]Variant);
    try std.testing.expectEqualStrings("av", s);
}

test "dbus array struct sig gen" {
    const s = generateDbusSignature([]struct { DbusObject, u32 });
    try std.testing.expectEqualStrings("a(ou)", s);
}

test "dbus map struct sig gen" {
    const s = generateDbusSignature([]DbusKV(DbusObject, DbusString));
    try std.testing.expectEqualStrings("a{os}", s);
}

const ConnectionFixture = struct {
    // From perspective of fixture holder, invert tx/rx for perspective of
    // dbus connection
    tx: sphtud.util.IoPipe,
    tx_reader: sphtud.util.IoPipe.PipeReader,
    rx: sphtud.util.IoPipe,
    rx_reader: sphtud.util.IoPipe.PipeReader,
    alloc_buf: [1 * 1024 * 1024]u8,
    alloc: sphtud.alloc.BufAllocator,
    connection: DbusConnection,

    const Self = @This();

    fn initPinned(self: *Self) !void {
        self.alloc = sphtud.alloc.BufAllocator.init(&self.alloc_buf);
        self.tx = sphtud.util.IoPipe.init(try self.alloc.allocator().alloc(u8, 4096));
        self.tx_reader = self.tx.reader(try self.alloc.allocator().alloc(u8, 4096));
        self.rx = sphtud.util.IoPipe.init(try self.alloc.allocator().alloc(u8, 4096));
        self.rx_reader = self.rx.reader(try self.alloc.allocator().alloc(u8, 4096));

        self.connection = try dbusConnection(&self.tx_reader.interface, &self.rx.writer);

        try self.tx.writer.writeAll("OK\r\nAGREE_UNIX_FD\r\n");
        while (try self.connection.poll() != .initialized) {}
        try validateCommonInitialization(&self.rx_reader.interface);
    }
};

fn validateCommonInitialization(reader: *std.Io.Reader) !void {
    try std.testing.expectStringStartsWith(try reader.takeDelimiterInclusive('\n'), "\x00AUTH EXTERNAL");
    try std.testing.expectEqualStrings("NEGOTIATE_UNIX_FD\r\n", try reader.takeDelimiterInclusive('\n'));
    try std.testing.expectEqualStrings("BEGIN\r\n", try reader.takeDelimiterInclusive('\n'));

    // Strace hello from qdbus
    const hello_message = "\x6c\x01\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x6e\x00\x00\x00\x01\x01\x6f\x00\x15\x00\x00\x00\x2f\x6f\x72\x67\x2f\x66\x72\x65\x65\x64\x65\x73\x6b\x74\x6f\x70\x2f\x44\x42\x75\x73\x00\x00\x00\x06\x01\x73\x00\x14\x00\x00\x00\x6f\x72\x67\x2e\x66\x72\x65\x65\x64\x65\x73\x6b\x74\x6f\x70\x2e\x44\x42\x75\x73\x00\x00\x00\x00\x02\x01\x73\x00\x14\x00\x00\x00\x6f\x72\x67\x2e\x66\x72\x65\x65\x64\x65\x73\x6b\x74\x6f\x70\x2e\x44\x42\x75\x73\x00\x00\x00\x00\x03\x01\x73\x00\x05\x00\x00\x00\x48\x65\x6c\x6c\x6f\x00\x00\x00";
    try std.testing.expectEqualSlices(u8, hello_message, try reader.take(hello_message.len));
}

test "generated interface spotify play pause" {
    const mpris = @import("mpris");

    var fixture: ConnectionFixture = undefined;
    try fixture.initPinned();

    const interface = mpris.OrgMprisMediaPlayer2Player {
        .connection = &fixture.connection,
        .service = "org.mpris.MediaPlayer2.spotify",
        .object_path = "/org/mpris/MediaPlayer2",
    };

    _ = try interface.playPause();

    // Strace play pause from qdbus on spotify
    const play_pause_message = "\x6c\x01\x00\x01\x00\x00\x00\x00\x02\x00\x00\x00\x82\x00\x00\x00\x01\x01\x6f\x00\x17\x00\x00\x00\x2f\x6f\x72\x67\x2f\x6d\x70\x72\x69\x73\x2f\x4d\x65\x64\x69\x61\x50\x6c\x61\x79\x65\x72\x32\x00\x06\x01\x73\x00\x1e\x00\x00\x00\x6f\x72\x67\x2e\x6d\x70\x72\x69\x73\x2e\x4d\x65\x64\x69\x61\x50\x6c\x61\x79\x65\x72\x32\x2e\x73\x70\x6f\x74\x69\x66\x79\x00\x00\x02\x01\x73\x00\x1d\x00\x00\x00\x6f\x72\x67\x2e\x6d\x70\x72\x69\x73\x2e\x4d\x65\x64\x69\x61\x50\x6c\x61\x79\x65\x72\x32\x2e\x50\x6c\x61\x79\x65\x72\x00\x00\x00\x03\x01\x73\x00\x09\x00\x00\x00\x50\x6c\x61\x79\x50\x61\x75\x73\x65\x00\x00\x00\x00\x00\x00\x00";
    try std.testing.expectEqualSlices(u8, play_pause_message, try fixture.rx_reader.interface.take(play_pause_message.len));

    // Property retrieval
    {
        const volume_handle = try interface.getVolume();

        // Validate the request, traced from a working interaction
        const expected_volume_req = .{ 108, 1, 0, 1, 47, 0, 0, 0, 3, 0, 0, 0, 136, 0, 0, 0, 1, 1, 111, 0, 23, 0, 0, 0, 47, 111, 114, 103, 47, 109, 112, 114, 105, 115, 47, 77, 101, 100, 105, 97, 80, 108, 97, 121, 101, 114, 50, 0, 6, 1, 115, 0, 30, 0, 0, 0, 111, 114, 103, 46, 109, 112, 114, 105, 115, 46, 77, 101, 100, 105, 97, 80, 108, 97, 121, 101, 114, 50, 46, 115, 112, 111, 116, 105, 102, 121, 0, 0, 2, 1, 115, 0, 31, 0, 0, 0, 111, 114, 103, 46, 102, 114, 101, 101, 100, 101, 115, 107, 116, 111, 112, 46, 68, 66, 117, 115, 46, 80, 114, 111, 112, 101, 114, 116, 105, 101, 115, 0, 3, 1, 115, 0, 3, 0, 0, 0, 71, 101, 116, 0, 0, 0, 0, 0, 8, 1, 103, 0, 2, 115, 115, 0, 29, 0, 0, 0, 111, 114, 103, 46, 109, 112, 114, 105, 115, 46, 77, 101, 100, 105, 97, 80, 108, 97, 121, 101, 114, 50, 46, 80, 108, 97, 121, 101, 114, 0, 0, 0, 6, 0, 0, 0, 86, 111, 108, 117, 109, 101, 0 };
        try std.testing.expectEqualSlices(u8, &expected_volume_req, try fixture.rx_reader.interface.take(expected_volume_req.len));

        // Send the volume response, traced from a working interaction
        try fixture.tx.writer.writeAll(
            &.{ 108, 2, 1, 1, 16, 0, 0, 0, 83, 4, 0, 0, 48, 0, 0, 0, 6, 1, 115, 0, 7, 0, 0, 0, 58, 49, 46, 49, 55, 55, 56, 0, 8, 1, 103, 0, 1, 118, 0, 0, 5, 1, 117, 0, 3, 0, 0, 0, 7, 1, 115, 0, 7, 0, 0, 0, 58, 49, 46, 49, 50, 49, 50, 0, 1, 100, 0, 0, 0, 0, 0, 0, 55, 103, 55, 103, 55, 103, 231, 63 },
        );

        const retrieved_volume = blk: while (true) {
            const response = try fixture.connection.poll();
            switch (response) {
                .initialized, .none => {},
                .response => |params| {
                    if (params.handle.inner == volume_handle.inner) {
                        break :blk try mpris.OrgMprisMediaPlayer2Player.parseGetVolumeResponse(params.header);
                    }
                }
            }
        };

        // Ensure that our callback was called
        try std.testing.expectEqual(0.7313496604867628, retrieved_volume);
    }

    // Property modification
    {
        try interface.setVolumeProperty(1.0);

        // Traced from a working interaction
        const expected_volume_req = .{ 108, 1, 0, 1, 64, 0, 0, 0, 4, 0, 0, 0, 137, 0, 0, 0, 1, 1, 111, 0, 23, 0, 0, 0, 47, 111, 114, 103, 47, 109, 112, 114, 105, 115, 47, 77, 101, 100, 105, 97, 80, 108, 97, 121, 101, 114, 50, 0, 6, 1, 115, 0, 30, 0, 0, 0, 111, 114, 103, 46, 109, 112, 114, 105, 115, 46, 77, 101, 100, 105, 97, 80, 108, 97, 121, 101, 114, 50, 46, 115, 112, 111, 116, 105, 102, 121, 0, 0, 2, 1, 115, 0, 31, 0, 0, 0, 111, 114, 103, 46, 102, 114, 101, 101, 100, 101, 115, 107, 116, 111, 112, 46, 68, 66, 117, 115, 46, 80, 114, 111, 112, 101, 114, 116, 105, 101, 115, 0, 3, 1, 115, 0, 3, 0, 0, 0, 83, 101, 116, 0, 0, 0, 0, 0, 8, 1, 103, 0, 3, 115, 115, 118, 0, 0, 0, 0, 0, 0, 0, 0, 29, 0, 0, 0, 111, 114, 103, 46, 109, 112, 114, 105, 115, 46, 77, 101, 100, 105, 97, 80, 108, 97, 121, 101, 114, 50, 46, 80, 108, 97, 121, 101, 114, 0, 0, 0, 6, 0, 0, 0, 86, 111, 108, 117, 109, 101, 0, 1, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 240, 63 };
        try std.testing.expectEqualSlices(u8, &expected_volume_req, try fixture.rx_reader.interface.take(expected_volume_req.len));
    }
}
