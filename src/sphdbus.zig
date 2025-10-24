const std = @import("std");
const sphtud = @import("sphtud");
const builtin = @import("builtin");

fn waitForStartsWith(reader: *std.Io.Reader, start: []const u8, err: anyerror) !void {
    const response = try reader.takeDelimiterInclusive('\n');
    if (!std.mem.startsWith(u8, response, start)) {
        std.log.err("{s} is not {s}\n", .{ response, start });
        return err;
    }
}

pub fn generateCommonResponseHandler(comptime T: type, ctx: ?*anyopaque, comptime callback: *const fn (ctx: ?*anyopaque, T) anyerror!void) CompletionHandler {
    const genericCb = struct {
        fn f(ctx_2: ?*anyopaque, scratch: *sphtud.alloc.BufAllocator, endianness: DbusEndianness, signature: []const u8, body: []const u8) !void {
            const cp = scratch.checkpoint();
            defer scratch.restore(cp);
            const val = try dbusParseBody(T, scratch.allocator(), scratch.backLinear(), endianness, signature, body);
            try callback(ctx_2, val);
        }
    }.f;

    return .{
        .ctx = ctx,
        .vtable = &.{
            .onFinish = genericCb,
        },
    };
}

pub fn generateCommonResponseHandlerVariant(comptime T: type, ctx: ?*anyopaque, comptime callback: *const fn (ctx: ?*anyopaque, T) anyerror!void) CompletionHandler {
    const genericCb = struct {
        fn f(ctx_2: ?*anyopaque, scratch: *sphtud.alloc.BufAllocator, endianness: DbusEndianness, signature: []const u8, body: []const u8) !void {
            const cp = scratch.checkpoint();
            defer scratch.restore(cp);
            const val = try dbusParseBody(Variant, scratch.allocator(), scratch.backLinear(), endianness, signature, body);
            try callback(ctx_2, try val.toConcrete(T));
        }
    }.f;

    return .{
        .ctx = ctx,
        .vtable = &.{
            .onFinish = genericCb,
        },
    };
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
        const b = (try self.takeByte()) orelse return null;

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

    fn takeByte(self: SignatureTokenizer) !?u8 {
        return self.reader.takeByte() catch |e| {
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
            else => return error.Unimplemented,
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
    pos: u32,
    reader: *std.Io.Reader,

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

    fn readF64(self: *DbusMessageReader, endianness: DbusEndianness) !f64 {
        return @bitCast(try self.readI64(endianness));
    }

    fn readI64(self: *DbusMessageReader, endianness: DbusEndianness) !i64 {
        try self.alignForwards(8);
        const ret = try self.reader.takeInt(i64, endianness.toBuiltin());
        self.pos += 8;
        return ret;
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

    fn readVariant(self: *DbusMessageReader, alloc: ?std.mem.Allocator, endianness: DbusEndianness) !Variant {
        if (alloc == null) {
            std.debug.assert(self.reader.vtable == std.Io.Reader.fixed(&.{}).vtable);
        }

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
                return Variant{ .string = try dupeIfAlloc(alloc, u8, s) };
            },
            .object => {
                const s = try self.readStringLike(endianness);
                return Variant{ .object = try dupeIfAlloc(alloc, u8, s) };
            },
            .signature => {
                const s = try self.readSignature();
                return Variant{ .signature = try dupeIfAlloc(alloc, u8, s) };
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

pub const DbusHeader = struct {
    endianness: DbusEndianness,
    message_type: MsgType,
    flags: u8,
    major_version: DBusVersion,
    body_len: u32,
    serial: u32,
    header_fields: []const HeaderFieldKV,

    pub fn parse(alloc: std.mem.Allocator, io_reader: *std.Io.Reader) !DbusHeader {
        var dbus_reader = DbusMessageReader{
            .pos = 0,
            .reader = io_reader,
        };

        const endianness = try std.meta.intToEnum(DbusEndianness, try dbus_reader.readByte());
        const message_type = try std.meta.intToEnum(MsgType, try dbus_reader.readByte());
        const flags = try dbus_reader.readByte();
        const major_version = try std.meta.intToEnum(DBusVersion, try dbus_reader.readByte());
        const body_len = try dbus_reader.readU32(endianness);
        const serial = try dbus_reader.readU32(endianness);

        const header_field_len = try dbus_reader.readU32(endianness);

        const end_header_pos = dbus_reader.pos + header_field_len;

        var headers_tmp_buf: [100]HeaderFieldKV = undefined;
        var headers_tmp = std.ArrayList(HeaderFieldKV).initBuffer(&headers_tmp_buf);

        var body_signature: []const u8 = "";

        while (dbus_reader.pos < end_header_pos) {
            try dbus_reader.alignForwards(8);
            const header_field_byte = try dbus_reader.readByte();
            const header_field = std.meta.intToEnum(HeaderField, header_field_byte) catch return error.InvalidHeaderField;

            try headers_tmp.appendBounded(.{
                .typ = header_field,
                .val = try dbus_reader.readVariant(alloc, endianness),
            });

            if (header_field == .signature) {
                const last_val = headers_tmp.getLast().val;
                if (last_val != .signature) {
                    return error.InvalidSignature;
                }
                body_signature = last_val.signature;
            }
        }

        if (dbus_reader.pos != end_header_pos) return error.InvalidHeader;
        try dbus_reader.alignForwards(8);

        return .{
            .endianness = endianness,
            .message_type = message_type,
            .flags = flags,
            .major_version = major_version,
            .body_len = body_len,
            .serial = serial,
            .header_fields = try alloc.dupe(HeaderFieldKV, headers_tmp.items),
        };
    }

    pub fn call(serial: u32, path: []const u8, destionation: []const u8, interface: []const u8, member: []const u8, body: anytype, field_buf: []HeaderFieldKV) !DbusHeader {
        var header_fields = std.ArrayList(HeaderFieldKV).initBuffer(field_buf);
        try header_fields.appendSliceBounded(&.{
            .{
                .typ = .path,
                .val = .{ .object = path },
            },
            .{
                .typ = .destination,
                .val = .{ .string = destionation },
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

    pub fn getHeader(self: DbusHeader, header: HeaderField) ?Variant {
        for (self.header_fields) |f| {
            if (f.typ == header) {
                return f.val;
            }
        }

        return null;
    }

    pub fn signature(self: DbusHeader) ![]const u8 {
        const s = self.getHeader(.signature) orelse return "";
        switch (s) {
            .signature => |v| return v,
            else => return error.InvaliHeader,
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

pub const CompletionHandler = struct {
    ctx: ?*anyopaque,
    vtable: *const VTable,

    const VTable = struct {
        onFinish: *const fn (ctx: ?*anyopaque, scratch: *sphtud.alloc.BufAllocator, endianness: DbusEndianness, signature: []const u8, val: []const u8) anyerror!void,
    };

    fn onFinish(self: CompletionHandler, scratch: *sphtud.alloc.BufAllocator, endianness: DbusEndianness, signature: []const u8, val: []const u8) !void {
        try self.vtable.onFinish(self.ctx, scratch, endianness, signature, val);
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
        Variant => {
            try dbus_writer.writeVariant(val);
            return;
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

pub fn dbusParseBodyInner(comptime T: type, alloc: std.mem.Allocator, scratch: sphtud.alloc.LinearAllocator, endianness: DbusEndianness, dr: *DbusMessageReader) !T {
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
            return try dr.readVariant(null, endianness);
        },
        u32 => {
            return try dr.readU32(endianness);
        },
        f64 => {
            return try dr.readF64(endianness);
        },
        else => {},
    }

    switch (@typeInfo(T)) {
        .pointer => |pi| {
            std.debug.assert(pi.size == .slice);

            const array_len_bytes = try dr.readU32(endianness);
            const start = dr.pos;
            var builder = try sphtud.util.RuntimeSegmentedListLinearAlloc(pi.child).init(
                scratch.allocator(),
                scratch.allocator(),
                // FIXME: Update guesses
                100,
                1000,
            );

            while (dr.pos < start + array_len_bytes) {
                try builder.append(try dbusParseBodyInner(pi.child, alloc, scratch, endianness, dr));
            }

            return try builder.makeContiguous(alloc);
        },
        .@"struct" => |si| {
            var ret: T = undefined;
            try dr.alignForwards(8);
            inline for (si.fields) |field| {
                @field(ret, field.name) = try dbusParseBodyInner(field.type, alloc, scratch, endianness, dr);
            }
            return ret;
        },
        else => {},
    }

    @compileError("Unsupported type " ++ @typeName(T));
}

pub fn dbusParseBody(comptime T: type, alloc: std.mem.Allocator, scratch: sphtud.alloc.LinearAllocator, endianness: DbusEndianness, signature: []const u8, body: []const u8) !T {
    var reader = std.Io.Reader.fixed(body);

    if (!std.mem.eql(u8, signature, generateDbusSignature(T))) {
        std.log.err("Expected {s} got {s}\n", .{ generateDbusSignature(T), signature });
        return error.InvalidType;
    }

    try reader.fill(body.len);
    var body_reader = std.Io.Reader.fixed(reader.buffered());
    reader.toss(body.len);

    var dr = DbusMessageReader{
        .pos = 0,
        .reader = &body_reader,
    };

    return dbusParseBodyInner(T, alloc, scratch, endianness, &dr);
}


pub fn dbusConnection(comptime Loop: type, alloc: std.mem.Allocator, scratch: *sphtud.alloc.BufAllocator, reader: *std.net.Stream.Reader, writer: *std.net.Stream.Writer, on_initialized: anytype) !DbusConnection(Loop, @TypeOf(on_initialized)) {
    try sphtud.event.setNonblock(reader.getStream().handle);

    return .{
        .scratch = scratch,
        .writer = writer,
        .reader = reader,
        .serial = 2,
        .state = .{
            .initializing = try DbusConnectionInitializer.init(&writer.interface),
        },
        .on_initialized = on_initialized,
        .outstanding_requests = try .init(
            alloc,
            alloc,
            16,
            1024,
        ),
    };
}

pub fn DbusConnection(comptime Loop: type, comptime OnInitializedCtx: type) type {
    return struct {
        scratch: *sphtud.alloc.BufAllocator,
        reader: *std.net.Stream.Reader,
        writer: *std.net.Stream.Writer,
        serial: u32,
        state: union(enum) {
            initializing: DbusConnectionInitializer,
            ready,
        },
        on_initialized: OnInitializedCtx,
        outstanding_requests: sphtud.util.AutoHashMapLinear(u32, CompletionHandler),

        const Self = @This();

        pub fn handler(self: *Self) Loop.Handler {
            return .{
                .fd = self.reader.getStream().handle,
                .ptr = self,
                .vtable = &.{
                    .poll = poll,
                    .close = close,
                },
                .desired_events = .{
                    .read = true,
                    .write = false,
                },
            };
        }

        pub fn call(self: *Self, path: []const u8, destionation: []const u8, interface: []const u8, member: []const u8, body: anytype, on_finish: ?CompletionHandler) !void {
            var field_buf: [6]HeaderFieldKV = undefined;
            const to_send = try DbusHeader.call(
                self.serial,
                path,
                destionation,
                interface,
                member,
                body,
                &field_buf,
            );
            // We shouldn't have an outstanding request from 2^32 requests ago
            self.serial +%= 1;

            try to_send.serialize(&self.writer.interface, body);
            try self.writer.interface.flush();

            if (on_finish) |h| {
                try self.outstanding_requests.putNoClobber(to_send.serial, h);
            }
        }

        fn poll(ctx: ?*anyopaque, _: *Loop, _: sphtud.event.PollReason) Loop.PollResult {
            const self: *Self = @ptrCast(@alignCast(ctx));
            self.pollError() catch |e| switch (e) {
                error.ReadFailed => {
                    if (self.reader.getError()) |reader_err| switch (reader_err) {
                        error.WouldBlock => {
                            return .in_progress;
                        },
                        else => {
                            std.log.err("read failed, closing connection: {t}", .{reader_err});
                            return .complete;
                        },
                    };
                },
                else => {
                    std.log.err("Closing connection: {t}", .{e});
                    return .complete;
                },
            };

            return .in_progress;
        }

        fn pollError(self: *Self) !void {
            sw: switch (self.state) {
                .initializing => |*initializer| {
                    if (!try initializer.poll(self.reader.interface(), &self.writer.interface)) {
                        return;
                    }
                    self.state = .ready;
                    try self.on_initialized.notify(self);
                    continue :sw self.state;
                },
                .ready => {
                    try self.pollReady();
                },
            }
        }

        fn pollReady(self: *Self) !void {
            const io_reader: *std.Io.Reader = self.reader.interface();
            while (true) {
                // It's easier to parse from a buffer than it is to write
                // DbusHeader.parse in a way where it doesn't consume bytes from
                // the reader for a partial read. Fill in outer loop as much as
                // possible, then if the parse fails below because there wasn't
                // enough data, we can just fill again until we return WouldBlock
                // here
                try io_reader.fillMore();

                while (true) {
                    const cp = self.scratch.checkpoint();
                    defer self.scratch.restore(cp);

                    var tmp_reader = std.Io.Reader.fixed(io_reader.buffered());

                    const message = DbusHeader.parse(self.scratch.allocator(), &tmp_reader) catch |e| switch (e) {
                        error.EndOfStream => break,
                        else => return e,
                    };

                    const body_buf = try self.scratch.allocator().alloc(u8, message.body_len);
                    _ = try tmp_reader.readSliceAll(body_buf);

                    io_reader.toss(tmp_reader.seek);

                    var reply_for: ?u32 = null;
                    for (message.header_fields) |f| {
                        if (f.typ == .reply_serial) {
                            if (f.val != .u32) break;
                            reply_for = f.val.u32;
                        }
                    }

                    if (reply_for) |rf| {
                        if (self.outstanding_requests.remove(rf)) |h| {
                            h.onFinish(self.scratch, message.endianness, try message.signature(), body_buf) catch |e| {
                                std.log.err("Failed to call handler: {t}", .{e});
                                if (@errorReturnTrace()) |st| {
                                    std.log.err("stack trace: {f}", .{st});
                                }
                            };
                        }
                    }
                }
            }
        }

        fn close(ctx: ?*anyopaque) void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            self.reader.getStream().close();
        }
    };
}

pub const DbusObject = struct {
    inner: []const u8,
};

pub const DbusString = struct {
    inner: []const u8,
};

pub fn DbusKV(comptime Key: type, comptime Val: type) type {
    return struct {
        // For metaprogramming :)
        pub const DbusKVFlag = {};

        key: Key,
        val: Val,
    };
}

fn generateDbusSignatureInner(comptime T: type, depth: usize) []const u8 {
    switch (T) {
        DbusString => return "s",
        DbusObject => return "o",
        i64 => return "x",
        u32 => return "u",
        Variant => return "v",
        f64 => return "d",
        else => {},
    }

    switch (@typeInfo(T)) {
        .pointer => |pi| {
            std.debug.assert(pi.size == .slice);

            return "a" ++ generateDbusSignatureInner(pi.child, depth + 1);
        },
        .@"struct" => |si| {
            const struct_open = if (@hasDecl(T, "DbusKVFlag")) "{" else "(";
            const struct_close = if (@hasDecl(T, "DbusKVFlag")) "}" else ")";

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

fn ConnectionFixture(comptime OnInitializedCtx: type) type {
    return struct {
        alloc_buf: [1 * 1024 * 1024]u8,
        alloc: sphtud.alloc.BufAllocator,
        scratch_buf: [1 * 1024 * 1024]u8,
        scratch: sphtud.alloc.BufAllocator,
        socket: std.net.Stream,
        dbus_reader: std.net.Stream.Reader,
        dbus_writer: std.net.Stream.Writer,
        connection: DbusConnection(sphtud.event.LoopLinear, OnInitializedCtx),
        loop: sphtud.event.LoopLinear,

        dbus_written: std.net.Stream.Reader,

        const Self = @This();

        fn initPinned(self: *Self, initializer: OnInitializedCtx) !void {
            var sockets: [2]std.posix.fd_t = undefined;
            const ret: isize = @bitCast(std.os.linux.socketpair(
                std.os.linux.AF.UNIX,
                std.os.linux.SOCK.STREAM | std.os.linux.SOCK.CLOEXEC | std.os.linux.SOCK.NONBLOCK,
                0,
                &sockets,
            ));

            if (ret < 0) {
                return error.CreateSockets;
            }

            self.socket = .{
                .handle = sockets[1],
            };

            const dbus_socket = std.net.Stream {
                .handle = sockets[0],
            };

            self.alloc = sphtud.alloc.BufAllocator.init(&self.alloc_buf);
            self.scratch = sphtud.alloc.BufAllocator.init(&self.scratch_buf);

            self.dbus_reader = dbus_socket.reader(
                try self.alloc.allocator().alloc(u8, 4096),
            );

            self.dbus_writer = dbus_socket.writer(
                try self.alloc.allocator().alloc(u8, 4096),
            );

            self.connection = try dbusConnection(sphtud.event.LoopLinear, self.alloc.allocator(), &self.scratch, &self.dbus_reader, &self.dbus_writer, initializer);
            self.dbus_written = self.socket.reader(
                try self.alloc.allocator().alloc(u8, 4096),
            );
            self.loop = try .init(self.alloc.allocator(), self.alloc.allocator());
            try self.loop.register(self.connection.handler());

            var w = self.socket.writer(&.{});
            try w.interface.writeAll("OK\r\nAGREE_UNIX_FD\r\nBEGIN\r\n");
        }
    };

}

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

    const OnInitialized = struct {
        fixture: *ConnectionFixture(@This()),

        pub fn notify(self: @This(), connection: anytype) !void {

            const interface = mpris.OrgMprisMediaPlayer2Player.interface(connection, "org.mpris.MediaPlayer2.spotify", "/org/mpris/MediaPlayer2");
            try interface.playPause(null, null);
            self.fixture.loop.shutdown();
        }
    };

    var fixture: ConnectionFixture(OnInitialized) = undefined;
    try fixture.initPinned(OnInitialized{ .fixture = &fixture });

    try fixture.loop.wait(fixture.scratch.linear());

    const reader: *std.Io.Reader = fixture.dbus_written.interface();

    try validateCommonInitialization(reader);

    // Strace play pause from qdbus no spotify
    const play_pause_message = "\x6c\x01\x00\x01\x00\x00\x00\x00\x02\x00\x00\x00\x82\x00\x00\x00\x01\x01\x6f\x00\x17\x00\x00\x00\x2f\x6f\x72\x67\x2f\x6d\x70\x72\x69\x73\x2f\x4d\x65\x64\x69\x61\x50\x6c\x61\x79\x65\x72\x32\x00\x06\x01\x73\x00\x1e\x00\x00\x00\x6f\x72\x67\x2e\x6d\x70\x72\x69\x73\x2e\x4d\x65\x64\x69\x61\x50\x6c\x61\x79\x65\x72\x32\x2e\x73\x70\x6f\x74\x69\x66\x79\x00\x00\x02\x01\x73\x00\x1d\x00\x00\x00\x6f\x72\x67\x2e\x6d\x70\x72\x69\x73\x2e\x4d\x65\x64\x69\x61\x50\x6c\x61\x79\x65\x72\x32\x2e\x50\x6c\x61\x79\x65\x72\x00\x00\x00\x03\x01\x73\x00\x09\x00\x00\x00\x50\x6c\x61\x79\x50\x61\x75\x73\x65\x00\x00\x00\x00\x00\x00\x00";
    try std.testing.expectEqualSlices(u8, play_pause_message, try reader.take(play_pause_message.len));
}

test "generated interface spotify volume property get" {
    // :) have fun :)
    unreachable;
}
