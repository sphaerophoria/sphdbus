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

fn waitForStartsWith(reader: *std.Io.Reader, start: []const u8, err: DbusError) DbusError!void {
    const response = reader.takeDelimiterInclusive('\n') catch |e| switch (e) {
        error.EndOfStream, error.ReadFailed => |t| return t,
        error.StreamTooLong => return DbusError.ParseError,
    };

    if (!std.mem.startsWith(u8, response, start)) {
        std.log.err("{s} is not {s}\n", .{ response, start });
        return err;
    }
}

pub const SignatureTokenizer = struct {
    reader: *std.Io.Reader,
    diagnostics: ?*DbusErrorDiagnostics,

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
        signature,
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
            'g' => .signature,
            else => {
                return makeDbusParseError(
                    self.diagnostics,
                    self.reader,
                    error.UnhandledSignature,
                    "unhandled type {c}",
                    .{b},
                );
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

const HeaderFieldTag = enum(u8) {
    path = 1,
    interface = 2,
    member = 3,
    error_name = 4,
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
        const len_u32 = std.math.cast(u32, data.len) orelse return error.SerializeError;
        try self.writer.writeAll(data);
        self.pos += len_u32;
    }

    fn writeVariantTag(self: *DbusMessageWriter, tag: []const u8) !void {
        const tag_len_u8 = std.math.cast(u8, tag.len) orelse return error.SerializeError;
        try self.writer.writeByte(tag_len_u8);
        self.pos += 1;

        try self.writer.writeAll(tag);
        self.pos += tag_len_u8;

        try self.writer.writeByte(0);
        self.pos += 1;
    }

    fn writeVariant(self: *DbusMessageWriter, val: anytype) !void {
        try self.writeVariantTag(generateDbusSignature(@TypeOf(val)));
        try dbusSerializeInner(self, val);
    }

    fn writeStringLike(self: *DbusMessageWriter, s: []const u8) !void {
        const s_len_u32 = std.math.cast(u32, s.len) orelse return error.SerializeError;
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
    reader: *std.Io.Reader,

    fn toss(self: *DbusMessageReader, amount: u32) void {
        self.reader.toss(amount);
    }

    fn readByte(self: *DbusMessageReader) !u8 {
        return try self.reader.takeByte();
    }

    fn readBytes(self: *DbusMessageReader, n: u32) ![]const u8 {
        return try self.reader.take(n);
    }

    fn readU32(self: *DbusMessageReader, endianness: DbusEndianness) !u32 {
        try self.alignForwards(4);
        return try self.reader.takeInt(u32, endianness.toBuiltin());
    }

    fn readI32(self: *DbusMessageReader, endianness: DbusEndianness) !i32 {
        return @bitCast(try self.readU32(endianness));
    }

    fn readU64(self: *DbusMessageReader, endianness: DbusEndianness) !u64 {
        try self.alignForwards(8);
        return try self.reader.takeInt(u64, endianness.toBuiltin());
    }

    fn readF64(self: *DbusMessageReader, endianness: DbusEndianness) !f64 {
        return @bitCast(try self.readU64(endianness));
    }

    fn readI64(self: *DbusMessageReader, endianness: DbusEndianness) !i64 {
        return @bitCast(try self.readU64(endianness));
    }

    fn alignForwards(self: *DbusMessageReader, alignment: u32) !void {
        const new_pos = std.mem.alignForward(usize, self.reader.seek, alignment);
        try self.reader.discardAll(new_pos - self.reader.seek);
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

    fn readVariant(self: *DbusMessageReader, endianness: DbusEndianness, diagnostics: ?*DbusErrorDiagnostics) ParseError!ParseVariant {
        std.debug.assert(self.reader.vtable == std.Io.Reader.fixed(&.{}).vtable);

        const data_start = self.reader.seek;

        const signature_s = try self.readSignature();
        var signature_reader = std.Io.Reader.fixed(signature_s);
        var signature_it = SignatureTokenizer{
            .reader = &signature_reader,
            .diagnostics = diagnostics,
        };

        const Tag = enum {
            array,
            @"struct",
        };
        var tag_stack_buf: [10]Tag = undefined;
        var tag_stack = std.ArrayList(Tag).initBuffer(&tag_stack_buf);

        // FIXME: Is there a way to merge this loop and the one in
        // dbusParseBodyInner? Maybe we work off the signature in both or
        // something?

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
                        const next_token = try signature_it.next() orelse {
                            return makeDbusParseError(
                                diagnostics,
                                signature_it.reader,
                                error.InvalidArraySignature,
                                "signature missing array type",
                                .{},
                            );
                        };
                        // FIXME: HACK HACK HACK
                        signature_it.reader.seek = cp;
                        switch (next_token) {
                            .u64, .f64, .i64, .kv_start, .struct_start => try self.alignForwards(8),
                            .array_start, .bool, .u32, .i32, .string, .object => try self.alignForwards(4),
                            .kv_end, .struct_end => {
                                return makeDbusParseError(diagnostics, signature_it.reader, error.InvalidArraySignature, "{t} is not a valid array type", .{next_token});
                            },
                            .signature, .variant => {},
                        }
                        self.toss(len_bytes);
                    }
                    tag_stack.appendBounded(.array) catch |e| {
                        return makeDbusParseError(
                            diagnostics,
                            signature_it.reader,
                            e,
                            "signature is too large",
                            .{},
                        );
                    };
                },
                .kv_start, .struct_start => {
                    if (!in_array) {
                        try self.alignForwards(8);
                    }
                    tag_stack.appendBounded(.@"struct") catch |e| {
                        return makeDbusParseError(
                            diagnostics,
                            signature_it.reader,
                            e,
                            "signature is too large",
                            .{},
                        );
                    };
                },
                .struct_end, .kv_end => {
                    const last_tag = tag_stack.pop();
                    std.debug.assert(last_tag == .@"struct");
                },
                .bool,
                .u32,
                .i32,
                => {
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
                        _ = try self.readVariant(endianness, diagnostics);
                    }
                },
                .signature => {
                    if (!in_array) {
                        _ = try self.readSignature();
                    }
                },
            }

            switch (token) {
                .struct_end, .kv_end, .bool, .u32, .i32, .u64, .i64, .f64, .object, .string, .signature, .variant => {
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

pub const ParseVariant = struct {
    signature_len: u32,
    variant_start: u32,
    data: []const u8,

    pub fn signature(self: ParseVariant) []const u8 {
        return self.data[self.variant_start + 1 .. self.variant_start + self.signature_len + 1];
    }

    pub fn toConcrete(self: ParseVariant, comptime T: type, endianness: DbusEndianness, options: ParseOptions) ParseError!T {
        var io_reader = std.Io.Reader.fixed(self.data);

        const expected_sig = generateDbusSignature(T);
        const actual_sig = self.data[self.variant_start + 1 .. self.variant_start + self.signature_len + 1];
        if (!std.mem.eql(u8, expected_sig, actual_sig)) {
            return makeDbusParseError(
                options.diagnostics,
                &io_reader,
                error.InvalidSignature,
                "Expected signature {s} does not match actual {s}",
                .{ expected_sig, actual_sig },
            );
        }

        var dr = DbusMessageReader{
            .reader = &io_reader,
        };
        dr.toss(self.variant_start + self.signature_len + 2);

        return dbusParseBodyInner(T, endianness, &dr, options.diagnostics);
    }
};

pub fn SerializationVariant(comptime T: type) type {
    return struct {
        // For metaprogramming :)
        pub const DbusVariantMarker = {};

        inner: T,
    };
}

pub fn serializationVariant(val: anytype) SerializationVariant(@TypeOf(val)) {
    return .{ .inner = val };
}

pub const HeaderField = union(HeaderFieldTag) {
    path: DbusObject,
    interface: DbusString,
    member: DbusString,
    error_name: DbusString,
    reply_serial: u32,
    destination: DbusString,
    sender: DbusString,
    signature: DbusSignature,
};

pub const Headers = struct {
    path: ?DbusObject = null,
    interface: ?DbusString = null,
    member: ?DbusString = null,
    error_name: ?DbusString = null,
    reply_serial: ?u32 = null,
    destination: ?DbusString = null,
    sender: ?DbusString = null,
    signature: ?DbusSignature = null,
};

const HeaderIt = struct {
    endianness: DbusEndianness,
    fixed_reader: std.Io.Reader,

    pub fn next(self: *HeaderIt, options: ParseOptions) ParseError!?HeaderField {
        std.debug.assert(self.fixed_reader.vtable == std.Io.Reader.fixed(&.{}).vtable);

        if (self.fixed_reader.seek == self.fixed_reader.buffer.len) {
            return null;
        }

        var dbus_reader = DbusMessageReader{
            .reader = &self.fixed_reader,
        };

        try dbus_reader.alignForwards(8);
        const header_field_byte = try dbus_reader.readByte();
        const header_field = std.meta.intToEnum(HeaderFieldTag, header_field_byte) catch {
            return makeDbusParseError(
                options.diagnostics,
                &self.fixed_reader,
                error.InvalidHeaderField,
                "{c} is not a valid header field",
                .{header_field_byte},
            );
        };

        switch (header_field) {
            inline else => |t| {
                const T = @FieldType(HeaderField, @tagName(t));
                const v = try dbusParseBodyInner(ParseVariant, self.endianness, &dbus_reader, options.diagnostics);
                return @unionInit(HeaderField, @tagName(t), try v.toConcrete(T, self.endianness, options));
            },
        }
    }
};

pub const ParsedMessage = struct {
    endianness: DbusEndianness,
    message_type: MsgType,
    flags: u8,
    major_version: DBusVersion,
    serial: u32,
    headers: Headers,
    body: []const u8,
    bytes_consumed: usize,

    pub fn parse(buf: []const u8, diagnostics: ?*DbusErrorDiagnostics) ParseError!ParsedMessage {
        var io_reader = std.Io.Reader.fixed(buf);

        var dbus_reader = DbusMessageReader{
            .reader = &io_reader,
        };

        const endianness_byte = try dbus_reader.readByte();
        const endianness = std.meta.intToEnum(DbusEndianness, endianness_byte) catch {
            return makeDbusParseError(
                diagnostics,
                &io_reader,
                error.InvalidEndianness,
                "{c} is not a valid dbus endianness",
                .{endianness_byte},
            );
        };
        const message_type_byte = try dbus_reader.readByte();
        const message_type = std.meta.intToEnum(MsgType, message_type_byte) catch {
            return makeDbusParseError(
                diagnostics,
                &io_reader,
                error.InvalidMessageType,
                "{d} is not a valid dbus message type",
                .{message_type_byte},
            );
        };
        const flags = try dbus_reader.readByte();
        const version_byte = try dbus_reader.readByte();
        const major_version = std.meta.intToEnum(DBusVersion, version_byte) catch {
            return makeDbusParseError(
                diagnostics,
                &io_reader,
                error.InvalidVersion,
                "{d} is not a valid dbus version",
                .{version_byte},
            );
        };
        const body_len = try dbus_reader.readU32(endianness);
        const serial = try dbus_reader.readU32(endianness);

        const header_field_len = try dbus_reader.readU32(endianness);

        try dbus_reader.alignForwards(8);

        const header_buf = try dbus_reader.readBytes(header_field_len);
        var header_it = HeaderIt {
            .endianness = endianness,
            .fixed_reader = std.Io.Reader.fixed(header_buf),
        };

        var headers = Headers{};
        while (try header_it.next(.{ .diagnostics = diagnostics })) |f| switch (f) {
            inline else => |v, t| {
                @field(headers, @tagName(t)) = v;
            }
        };

        try dbus_reader.alignForwards(8);
        const body = try dbus_reader.readBytes(body_len);

        return .{
            .endianness = endianness,
            .message_type = message_type,
            .flags = flags,
            .major_version = major_version,
            .serial = serial,
            .headers = headers,
            .body = body,
            .bytes_consumed = dbus_reader.reader.seek,
        };
    }
};

pub const DbusHeader = struct {
    endianness: DbusEndianness,
    message_type: MsgType,
    flags: u8,
    major_version: DBusVersion,
    body_len: u32,
    serial: u32,
    header_fields: []const HeaderField,

    pub fn call(serial: u32, path: []const u8, destination: []const u8, interface: []const u8, member: []const u8, body: anytype, field_buf: []HeaderField) !DbusHeader {
        var header_fields = std.ArrayList(HeaderField).initBuffer(field_buf);
        try header_fields.appendSliceBounded(&.{
            .{
                .path = .{ .inner = path },
            },
            .{
                .destination = .{ .inner = destination },
            },
            .{
                .interface = .{ .inner = interface },
            },
            .{
                .member = .{ .inner = member },
            },
        });

        const body_signature = generateDbusSignature(@TypeOf(body));

        if (body_signature.len > 0) {
            try header_fields.appendBounded(.{
                .signature = .{ .inner = body_signature },
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

    pub fn ret(serial: u32, reply_serial: u32, destination: []const u8, body: anytype, field_buf: []HeaderField) !DbusHeader {
        var header_fields = std.ArrayList(HeaderField).initBuffer(field_buf);
        try header_fields.appendSliceBounded(&.{
            .{
                .destination = .{ .inner = destination },
            },
            .{
                .reply_serial = reply_serial,
            },
        });

        const body_signature = generateDbusSignature(@TypeOf(body));

        if (body_signature.len > 0) {
            try header_fields.appendBounded(.{
                .signature = .{ .inner = body_signature },
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

    pub fn err(serial: u32, reply_serial: u32, destination: []const u8, err_name: DbusString, body: ?DbusString, field_buf: []HeaderField) !DbusHeader {
        var header_fields = std.ArrayList(HeaderField).initBuffer(field_buf);
        try header_fields.appendSliceBounded(&.{
            .{
                .destination = .{ .inner = destination },
            },
            .{
                .error_name = err_name,
            },
            .{
                .reply_serial = reply_serial,
            },
        });

        var discarding_writer = std.Io.Writer.Discarding.init(&.{});

        if (body) |s| {
            try header_fields.appendBounded(.{
                .signature = .{ .inner = "s" },
            });

            try dbusSerialize(&discarding_writer.writer, s);
        }

        return DbusHeader{
            .endianness = .little,
            .message_type = .err,
            .flags = 0,
            .major_version = .@"1",
            .body_len = @intCast(discarding_writer.fullCount()),
            .serial = serial,
            .header_fields = header_fields.items,
        };
    }

    fn serialize(self: DbusHeader, io_writer: *std.Io.Writer, body: anytype) DbusError!void {
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
            try header_field_writer.writeByte(@intFromEnum(header_field));
            switch (header_field) {
                inline else => |v| try header_field_writer.writeVariant(v),
            }
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

    fn poll(self: *DbusConnectionInitializer, io_reader: *std.Io.Reader, io_writer: *std.Io.Writer) DbusError!bool {
        sw: switch (self.state) {
            .wait_for_ok => {
                try waitForStartsWith(io_reader, "OK", error.ParseError);

                try io_writer.print("NEGOTIATE_UNIX_FD\r\n", .{});
                try io_writer.flush();

                self.state = .wait_for_ack;
                continue :sw self.state;
            },
            .wait_for_ack => {
                try waitForStartsWith(io_reader, "AGREE_UNIX_FD", error.ParseError);

                try io_writer.print("BEGIN\r\n", .{});

                const hello_message = DbusHeader{
                    .endianness = .little,
                    .message_type = .call,
                    .flags = 0,
                    .major_version = .@"1",
                    .body_len = 0,
                    .serial = 1,
                    .header_fields = &.{
                        .{ .path = .{ .inner = "/org/freedesktop/DBus" } },
                        .{ .destination = .{ .inner = "org.freedesktop.DBus" } },
                        .{ .interface = .{ .inner = "org.freedesktop.DBus" } },
                        .{ .member = .{ .inner = "Hello" } },
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
        DbusSignature => {
            const len = std.math.cast(u8, val.inner.len) orelse return error.SerializeError;
            try dbus_writer.writeByte(len);
            try dbus_writer.writeAll(val.inner);
            try dbus_writer.writeByte(0);
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
        else => {},
    }

    switch (@typeInfo(@TypeOf(val))) {
        .@"struct" => |si| {
            if (@hasDecl(@TypeOf(val), "DbusVariantMarker")) {
                try dbus_writer.writeVariant(val.inner);
            } else {
                try dbus_writer.alignForwards(8);
                inline for (si.fields) |field| {
                    try dbusSerializeInner(dbus_writer, @field(val, field.name));
                }
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
        ParseVariant => return 1,
        u64, f64, i64 => return 8,
        else => {},
    }

    switch (@typeInfo(T)) {
        .@"struct" => {
            if (@hasDecl(T, "ParseArrayMarker")) return 4;
            return 8;
        },
        else => {},
    }

    @compileError("Unknown alignment for " ++ @typeName(T));
}

pub fn dbusParseBodyInner(comptime T: type, endianness: DbusEndianness, dr: *DbusMessageReader, diagnostics: ?*DbusErrorDiagnostics) ParseError!T {
    switch (T) {
        DbusObject, DbusString => {
            const string_len = try dr.readU32(endianness);
            // Known that string content lives in body, so it's ok
            const s = try dr.readBytes(string_len);
            _ = try dr.readBytes(1);

            return .{ .inner = s };
        },
        DbusSignature => {
            return .{ .inner = try dr.readSignature() };
        },
        ParseVariant => {
            return try dr.readVariant(endianness, diagnostics);
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
            if (@hasDecl(T, "ParseArrayMarker")) {
                const array_len_bytes = try dr.readU32(endianness);
                try dr.alignForwards(getDbusAlignment(T.T));

                const start = dr.reader.seek;
                dr.toss(array_len_bytes);

                // Align forwards to inner Type alignment
                // consume array_len_bytes

                return .{
                    .start = @intCast(start),
                    .endianness = endianness,
                    .data = dr.reader.buffer[0..dr.reader.seek],
                };
            }
            var ret: T = undefined;
            try dr.alignForwards(8);
            inline for (si.fields) |field| {
                @field(ret, field.name) = try dbusParseBodyInner(field.type, endianness, dr, diagnostics);
            }
            return ret;
        },
        else => {},
    }

    @compileError("Unsupported type " ++ @typeName(T));
}

pub fn dbusParseBody(comptime T: type, message: ParsedMessage, options: ParseOptions) ParseError!T {
    var reader = std.Io.Reader.fixed(message.body);

    const signature = message.headers.signature orelse return {
        return makeDbusParseError(
            options.diagnostics,
            &reader,
            error.NoSignature,
            "parsing element with no signature",
            .{},
        );
    };
    const expected_sig = generateDbusSignature(T);

    if (!std.mem.eql(u8, signature.inner, generateDbusSignature(T))) {
        return makeDbusParseError(
            options.diagnostics,
            &reader,
            error.InvalidType,
            "type signature is {s} but parsed is {s}",
            .{ expected_sig, signature.inner },
        );
    }

    var dr = DbusMessageReader{
        .reader = &reader,
    };

    // FIXME: null diagnostics seems wrong
    return dbusParseBodyInner(T, message.endianness, &dr, options.diagnostics);
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

pub const ParseError = error{ParseError} || std.Io.Reader.Error;
pub const SerializeError = error{SerializeError} || std.Io.Writer.Error;

pub const DbusError = error{
    Unrecoverable,
} || ParseError || SerializeError;

pub const DbusErrorDiagnostics = struct {
    // FIXME: Maybe an enum instead of polluting error space?
    error_reason: ?anyerror,

    parse_context: []const u8,
    error_pos: usize,

    message_buf: []u8,
    message_len: usize,

    pub fn init(message_buf: []u8) DbusErrorDiagnostics {
        return .{
            .error_reason = null,
            .parse_context = &.{},
            .error_pos = 0,
            .message_buf = message_buf,
            .message_len = 0,
        };
    }

    pub fn message(self: DbusErrorDiagnostics) []const u8 {
        return self.message_buf[0..self.message_len];
    }

    pub fn dumpPacket(self: DbusErrorDiagnostics, w: *std.Io.Writer) !void {
        var line_it: usize = 0;

        const line_tag_width = (std.math.log2(self.parse_context.len) + 3) / 4;

        while (line_it < self.parse_context.len) {
            defer line_it += 16;

            var it = line_it;
            const align_end = line_it + 16;
            const line_end = @min(align_end, self.parse_context.len);

            try w.printInt(line_it, 16, .lower, .{
                .fill = '0',
                .width = line_tag_width,
            });

            try w.writeAll(" | ");
            while (it < line_end) : (it += 1) {
                try w.printInt(self.parse_context[it], 16, .lower, .{
                    .fill = '0',
                    .width = 2,
                });
                try w.writeByte(' ');
            }

            try w.splatByteAll(' ', (align_end - it) * 3);
            try w.writeAll(" | ");
            it = line_it;

            while (it < line_end) : (it += 1) {
                var c = self.parse_context[it];

                if (!std.ascii.isAlphanumeric(c)) {
                    c = '.';
                }
                try w.writeByte(c);
            }

            try w.splatByteAll(' ', (align_end - it));
            try w.writeAll(" |\n");

            if (self.error_pos >= line_it and self.error_pos < line_it + 16) {
                try w.splatByteAll(' ', (self.error_pos - line_it) * 3 + line_tag_width + 3);
                try w.writeAll("^\n");
            }
        }
    }
};

pub const ParseOptions = struct {
    diagnostics: ?*DbusErrorDiagnostics = null,
};

fn makeDbusParseError(diagnostics: ?*DbusErrorDiagnostics, reader: *std.Io.Reader, reason: anyerror, comptime msg: []const u8, args: anytype) error{ParseError} {
    if (diagnostics) |d| {
        d.error_reason = reason;
        d.parse_context = reader.buffer;
        d.error_pos = reader.seek;

        var w = std.Io.Writer.fixed(d.message_buf);
        w.print(msg, args) catch {};
        d.message_len = w.end;
    }

    return error.ParseError;
}

pub const CallHandle = struct { inner: u32 };

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

        var field_buf: [6]HeaderField = undefined;
        const to_send = try DbusHeader.call(
            self.serial,
            path,
            destination,
            interface,
            member,
            body,
            &field_buf,
        );
        const handle = CallHandle{ .inner = self.serial };
        // We shouldn't have an outstanding request from 2^32 requests ago
        self.serial +%= 1;

        try to_send.serialize(self.writer, body);
        try self.writer.flush();

        return handle;
    }

    pub fn ret(self: *DbusConnection, reply_serial: u32, destination: []const u8, body: anytype) !void {
        if (self.state != .ready) return error.Uninitialized;

        var field_buf: [6]HeaderField = undefined;
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

    // FIXME: Duplication between ret/err/call
    pub fn err(self: *DbusConnection, reply_serial: u32, destination: []const u8, err_name: DbusString, body: ?DbusString) !void {
        if (self.state != .ready) return error.Uninitialized;

        var field_buf: [6]HeaderField = undefined;
        const to_send = try DbusHeader.err(
            self.serial,
            reply_serial,
            destination,
            err_name,
            body,
            &field_buf,
        );
        // We shouldn't have an outstanding request from 2^32 requests ago
        self.serial +%= 1;

        if (body) |b| {
            try to_send.serialize(self.writer, b);
        } else {
            try to_send.serialize(self.writer, .{});
        }

        try self.writer.flush();
    }

    pub const Response = union(enum) {
        initialized,
        call: ParsedMessage,
        response: struct {
            handle: CallHandle,
            header: ParsedMessage,
        },
        none,
    };

    pub fn poll(self: *Self, options: ParseOptions) !Response {
        switch (self.state) {
            .initializing => |*initializer| {
                if (!try initializer.poll(self.reader, self.writer)) {
                    return .none;
                }
                self.state = .ready;
                return .initialized;
            },
            .ready => {
                return self.pollReady(options);
            },
        }
    }

    fn pollReady(self: *Self, options: ParseOptions) DbusError!Response {
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
            const reader_buf = self.reader.buffered();

            const message = ParsedMessage.parse(reader_buf, options.diagnostics) catch |e| switch (e) {
                error.EndOfStream => return .none,
                // A header parse error will never resolve, and we have no way
                // to know how much data to consume if we cannot read the
                // header correctly. We need a full connection reset
                //
                // Note that diagnostics will already be populated with the
                // correct data, so no need to update it
                error.ParseError => return error.Unrecoverable,
                error.ReadFailed => return e,
            };

            self.reader.toss(message.bytes_consumed);

            if (message.headers.reply_serial) |rs| {
                return .{
                    .response = .{
                        .handle = .{ .inner = rs },
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

pub const DbusSignature = struct {
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

pub fn ParseArray(comptime Val: type) type {
    return struct {
        // For metaprogramming :)
        pub const ParseArrayMarker = {};
        pub const T = Val;

        start: u32,
        data: []const u8,
        endianness: DbusEndianness,

        const Iter = struct {
            offs: u32,
            data: []const u8,
            endianness: DbusEndianness,

            pub fn next(self: *Iter, options: ParseOptions) !?T {
                if (self.offs >= self.data.len) return null;

                var io_reader = std.Io.Reader.fixed(self.data);
                var reader = DbusMessageReader{
                    .reader = &io_reader,
                };
                reader.toss(self.offs);

                const ret = try dbusParseBodyInner(T, self.endianness, &reader, options.diagnostics);
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
        DbusSignature => return "g",
        i64 => return "x",
        u32 => return "u",
        i32 => return "i",
        u64 => return "t",
        ParseVariant => return "v",
        f64 => return "d",
        else => {},
    }

    switch (@typeInfo(T)) {
        .pointer => |pi| {
            if (pi.size == .slice) {
                return "a" ++ generateDbusSignatureInner(pi.child, depth + 1);
            }
        },
        .@"struct" => |si| {
            if (@hasDecl(T, "ParseArrayMarker")) {
                return "a" ++ generateDbusSignatureInner(T.T, depth + 1);
            }
            if (@hasDecl(T, "DbusVariantMarker")) {
                return "v";
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
    const s = generateDbusSignature([]SerializationVariant(u32));
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
        while (try self.connection.poll(.{}) != .initialized) {}
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

    const interface = mpris.OrgMprisMediaPlayer2Player{
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
            const response = try fixture.connection.poll(.{});
            switch (response) {
                .initialized, .call, .none => {},
                .response => |params| {
                    if (params.handle.inner == volume_handle.inner) {
                        break :blk try mpris.OrgMprisMediaPlayer2Player.parseGetVolumeResponse(params.header, .{});
                    }
                },
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
