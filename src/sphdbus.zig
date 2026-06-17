const std = @import("std");
const sphtud = if (builtin.is_test) @import("sphtud") else void;
const builtin = @import("builtin");

pub const service = @import("service.zig");

pub fn sessionBusPath(env: std.process.Environ) ![]const u8 {
    const session_address = env.getPosix("DBUS_SESSION_BUS_ADDRESS") orelse return error.NoSessionAddress;
    return try extractUnixPathFromAddress(session_address);
}

fn extractUnixPathFromAddress(address: []const u8) ![]const u8 {
    const tag = "unix:path=";
    if (!std.mem.startsWith(u8, address, tag)) return error.NotUnixPath;
    return address[tag.len..];
}

fn waitForStartsWith(reader: *std.Io.Reader, start: []const u8, err: PollError) PollError!void {
    const response = reader.takeDelimiterInclusive('\n') catch |e| switch (e) {
        error.EndOfStream, error.ReadFailed => |t| return t,
        error.StreamTooLong => return PollError.ParseError,
    };

    if (!std.mem.startsWith(u8, response, start)) {
        std.log.err("{s} is not {s}\n", .{ response, start });
        return err;
    }
}

pub const SignatureTokenizer = struct {
    reader: std.Io.Reader,
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
        byte,
    };

    pub fn next(self: *SignatureTokenizer) !?Token {
        const ret = (try self.peek()) orelse return null;
        self.reader.toss(1);
        return ret;
    }

    pub fn peek(self: *SignatureTokenizer) !?Token {
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
            'y' => .byte,
            else => {
                return makeDbusParseError(
                    self.diagnostics,
                    &self.reader,
                    error.UnhandledSignature,
                    "unhandled type {c}",
                    .{b},
                );
            },
        };
    }

    fn peekByte(self: *SignatureTokenizer) !?u8 {
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

const body_alignment = 8;

fn alignmentOf(t: DbusType) u8 {
    return switch (t) {
        .signature, .variant, .byte => 1,
        .bool, .i32, .u32, .array, .string, .object => 4,
        .f64, .kv, .i64, .u64, .@"struct" => 8,
    };
}

const DbusType = enum {
    byte,
    bool,
    variant,
    u32,
    u64,
    i32,
    i64,
    f64,
    array,
    string,
    object,
    kv,
    signature,
    @"struct",

    fn typeString(t: DbusType) u8 {
        return switch (t) {
            .byte => 'y',
            .bool => 'b',
            .variant => 'v',
            .u32 => 'u',
            .u64 => 't',
            .i32 => 'i',
            .i64 => 'x',
            .f64 => 'd',
            .array => 'a',
            .string => 's',
            .object => 'o',
            .kv => '{',
            .signature => 'g',
            .@"struct" => '(',
        };
    }

    fn fromType(comptime T: type) DbusType {
        switch (T) {
            u32 => return .u32,
            i32 => return .i32,
            DbusObject => return .object,
            DbusString => return .string,
            ParseVariant => return .variant,
            ParseArrayUntyped => return .array,
            u64 => return .u64,
            f64 => return .f64,
            i64 => return .i64,
            else => {},
        }

        switch (@typeInfo(T)) {
            .@"struct" => {
                if (@hasDecl(T, "ParseArrayMarker")) return .array;
                if (@hasDecl(T, "DbusKVMarker")) return .kv;
                if (@hasDecl(T, "DbusVariantMarker")) return .variant;
                return .@"struct";
            },
            .pointer => |pi| {
                if (pi.size == .slice) return .array;
            },
            else => {},
        }

        @compileError("Unknown type for " ++ @typeName(T));
    }

    fn fromToken(token: SignatureTokenizer.Token) !DbusType {
        return switch (token) {
            .array_start => .array,
            .struct_start => .@"struct",
            .struct_end => return error.InvalidToken,
            .kv_start => .kv,
            .kv_end => return error.InvalidToken,
            .u32 => .u32,
            .u64 => .u64,
            .i32 => .i32,
            .i64 => .i64,
            .f64 => .f64,
            .byte => .byte,
            .object => .object,
            .string => .string,
            .bool => .bool,
            .variant => .variant,
            .signature => .signature,
        };
    }
};

const ParseValue = union(DbusType) {
    byte: u8,
    bool: bool,
    variant: BodyReader,
    u32: u32,
    u64: u64,
    i32: i32,
    i64: i64,
    f64: f64,
    array: ParseArrayUntyped,
    string: DbusString,
    object: DbusObject,
    kv: BodyReader,
    signature: DbusSignature,
    @"struct": BodyReader,
};

const DbusMessageWriter = struct {
    pos: u32,
    writer: *std.Io.Writer,

    fn writeByte(self: *DbusMessageWriter, b: u8) !void {
        try self.writer.writeByte(b);
        self.pos += 1;
    }

    fn writeU32(self: *DbusMessageWriter, val: u32) !void {
        try self.alignForwards(alignmentOf(.u32));
        try self.writer.writeInt(u32, val, builtin.cpu.arch.endian());
        self.pos += 4;
    }

    fn writeI32(self: *DbusMessageWriter, val: i32) !void {
        try self.writeU32(@bitCast(val));
    }

    fn writeBool(self: *DbusMessageWriter, val: bool) !void {
        try self.writeU32(@intFromBool(val));
    }

    fn writeF64(self: *DbusMessageWriter, val: f64) !void {
        try self.writeU64(@bitCast(val));
    }

    fn writeI64(self: *DbusMessageWriter, val: i64) !void {
        try self.writeU64(@bitCast(val));
    }

    fn writeU64(self: *DbusMessageWriter, val: u64) !void {
        try self.alignForwards(alignmentOf(.u64));
        try self.writer.writeInt(u64, val, builtin.cpu.arch.endian());
        self.pos += 8;
    }

    fn writeSignatureBytes(self: *DbusMessageWriter, sig: []const u8) !void {
        const len = std.math.cast(u8, sig.len) orelse return error.SerializeError;
        try self.writeByte(len);
        try self.writeAll(sig);
        try self.writeByte(0);
    }

    fn writeAll(self: *DbusMessageWriter, data: []const u8) !void {
        const len_u32 = std.math.cast(u32, data.len) orelse return error.SerializeError;
        try self.writer.writeAll(data);
        self.pos += len_u32;
    }

    fn writeStringLike(self: *DbusMessageWriter, s: []const u8) !void {
        const s_len_u32 = std.math.cast(u32, s.len) orelse return error.SerializeError;
        try self.writeU32(s_len_u32);

        try self.writer.writeAll(s);
        self.pos += s_len_u32;

        try self.writer.writeByte(0);
        self.pos += 1;
    }

    pub fn alignForwards(self: *DbusMessageWriter, alignment: u8) !void {
        const new_pos = std.mem.alignForward(u32, self.pos, alignment);
        try self.writer.splatByteAll(0, new_pos - self.pos);
        self.pos = new_pos;
    }
};

const DbusMessageReader = struct {
    reader: std.Io.Reader,

    fn toss(self: *DbusMessageReader, amount: u32) void {
        self.reader.toss(amount);
    }

    fn discard(self: *DbusMessageReader, amount: u32) !void {
        try self.reader.discardAll(amount);
    }

    fn readByte(self: *DbusMessageReader) !u8 {
        return try self.reader.takeByte();
    }

    fn readBytes(self: *DbusMessageReader, n: u32) ![]const u8 {
        return try self.reader.take(n);
    }

    fn readBool(self: *DbusMessageReader, endianness: DbusEndianness) !bool {
        const ret = try self.readU32(endianness);
        if (ret > 1) return error.InvalidBool;
        return ret > 0;
    }

    fn readU32(self: *DbusMessageReader, endianness: DbusEndianness) !u32 {
        try self.alignForwards(alignmentOf(.u32));
        return try self.reader.takeInt(u32, endianness.toBuiltin());
    }

    fn readI32(self: *DbusMessageReader, endianness: DbusEndianness) !i32 {
        return @bitCast(try self.readU32(endianness));
    }

    fn readU64(self: *DbusMessageReader, endianness: DbusEndianness) !u64 {
        try self.alignForwards(alignmentOf(.u64));
        return try self.reader.takeInt(u64, endianness.toBuiltin());
    }

    fn readF64(self: *DbusMessageReader, endianness: DbusEndianness) !f64 {
        return @bitCast(try self.readU64(endianness));
    }

    fn readI64(self: *DbusMessageReader, endianness: DbusEndianness) !i64 {
        return @bitCast(try self.readU64(endianness));
    }

    fn alignForwards(self: *DbusMessageReader, alignment: u8) !void {
        const new_pos = std.mem.alignForward(usize, self.reader.seek, alignment);
        try self.reader.discardAll(new_pos - self.reader.seek);
    }

    fn readSignature(self: *DbusMessageReader) ![]const u8 {
        const signature_len = try self.readByte();
        return (try self.readBytes(signature_len + 1))[0..signature_len];
    }

    fn readStringLike(self: *DbusMessageReader, endianness: DbusEndianness) ![]const u8 {
        const len = try self.readU32(endianness);
        return (try self.readBytes(len + 1))[0..len];
    }

    fn tokenAlignment(token: SignatureTokenizer.Token) !u32 {
        return switch (token) {
            .u64, .f64, .i64, .kv_start, .struct_start => 8,
            .array_start, .bool, .u32, .i32, .string, .object => 4,
            .kv_end, .struct_end => {
                return error.InvalidToken;
            },
            .signature, .variant => 1,
        };
    }

    fn readStruct(self: *DbusMessageReader, tokenizer: *SignatureTokenizer, endianness: DbusEndianness, diagnostics: ?*DbusErrorDiagnostics) !BodyReader {
        std.debug.assert(self.reader.vtable == std.Io.Reader.fixed(&.{}).vtable);

        try self.alignForwards(alignmentOf(.@"struct"));

        const data_start = self.reader.seek;
        const sig_start = tokenizer.reader.seek;

        var pvc: ParseValueConsumer = undefined;
        pvc.initPinned(tokenizer, self, diagnostics);

        while (try pvc.nextToken()) |token| {
            if (pvc.tag_stack.stack.items.len == 0 and (token == .struct_end or token == .kv_end)) break;
            try pvc.handleToken(token, endianness);
        }

        var br = BodyReader.init(
            tokenizer.reader.buffer[sig_start .. tokenizer.reader.seek - 1],
            self.reader.buffer[0..self.reader.seek],
            endianness,
            .{ .diagnostics = diagnostics },
        );

        br.reader.toss(@intCast(data_start));
        return br;
    }

    fn readArray(self: *DbusMessageReader, tokenizer: *SignatureTokenizer, endianness: DbusEndianness, diagnostics: ?*DbusErrorDiagnostics) !ParseArrayUntyped {
        std.debug.assert(self.reader.vtable == std.Io.Reader.fixed(&.{}).vtable);

        try self.alignForwards(alignmentOf(.array));

        const sig_start = tokenizer.reader.seek;

        const arr_len = try self.readU32(endianness);

        // PVC is advancing the body reader, but we are manually calculating the length
        var pvc: ParseValueConsumer = undefined;
        pvc.initPinned(tokenizer, self, diagnostics);

        // Align forwards so that array length calculation starts at the start
        // of the first elem
        const first_elem_token = try pvc.tokenizer.peek() orelse return error.NoArrayElem;
        const first_elem_type = try DbusType.fromToken(first_elem_token);
        const first_item_alignment = alignmentOf(first_elem_type);
        try self.alignForwards(first_item_alignment);

        const data_start = self.reader.seek;

        try pvc.tag_stack.handleToken(.array_start);

        while (try pvc.nextToken()) |token| {
            if (pvc.tag_stack.stack.items.len == 0) break;
            try pvc.handleToken(token, endianness);
        }

        if (data_start + arr_len > self.reader.buffer.len) {
            return error.InvalidLen;
        }

        self.reader.seek = data_start + arr_len;
        var br = BodyReader.init(
            tokenizer.reader.buffer[sig_start..tokenizer.reader.seek],
            self.reader.buffer[0 .. data_start + arr_len],
            endianness,
            .{ .diagnostics = diagnostics },
        );

        br.reader.toss(@intCast(data_start));
        return .{ .br = br };
    }

    fn readVariant(self: *DbusMessageReader, endianness: DbusEndianness, diagnostics: ?*DbusErrorDiagnostics) ParseError!ParseVariant {
        std.debug.assert(self.reader.vtable == std.Io.Reader.fixed(&.{}).vtable);

        const signature_s = try self.readSignature();
        var signature_reader = SignatureTokenizer{
            .reader = .fixed(signature_s),
            .diagnostics = diagnostics,
        };

        const data_start = self.reader.seek;

        var pvc: ParseValueConsumer = undefined;
        pvc.initPinned(&signature_reader, self, diagnostics);

        while (try pvc.nextToken()) |token| {
            try pvc.handleToken(token, endianness);
        }

        var br = BodyReader.init(
            signature_s,
            self.reader.buffer,
            endianness,
            .{ .diagnostics = diagnostics },
        );

        br.reader.toss(@intCast(data_start));
        return .{ .inner = br };
    }
};

pub const ParseArrayUntyped = struct {
    br: BodyReader,

    pub fn next(self: *ParseArrayUntyped) ?*BodyReader {
        if (!self.br.hasData()) return null;
        self.br.tokenizer.reader.seek = 0;
        return &self.br;
    }
};

pub const BodyReader = struct {
    tokenizer: SignatureTokenizer,
    reader: DbusMessageReader,
    endianness: DbusEndianness,

    pub fn initMessage(message: ParsedMessage, options: ParseOptions) !BodyReader {
        const sig = message.headers.signature orelse return error.MissingSignature;
        return .init(sig.inner, message.body, message.endianness, options);
    }

    pub fn init(sig: []const u8, body: []const u8, endianness: DbusEndianness, options: ParseOptions) BodyReader {
        return .{
            .tokenizer = .{
                .diagnostics = options.diagnostics,
                .reader = .fixed(sig),
            },
            .reader = .{ .reader = .fixed(body) },
            .endianness = endianness,
        };
    }

    pub fn hasData(self: *BodyReader) bool {
        return self.reader.reader.bufferedLen() > 0;
    }

    pub fn next(self: *BodyReader) !?ParseValue {
        const token = try self.tokenizer.peek() orelse return null;
        const typ = try DbusType.fromToken(token);
        switch (typ) {
            .f64 => return .{ .f64 = try self.nextF64() },
            .u32 => return .{ .u32 = try self.nextU32() },
            .u64 => return .{ .u64 = try self.nextU64() },
            .i32 => return .{ .i32 = try self.nextI32() },
            .i64 => return .{ .i64 = try self.nextI64() },
            .byte => return .{ .byte = try self.nextByte() },
            .object => return .{ .object = try self.nextObject() },
            .string => return .{ .string = try self.nextString() },
            .bool => return .{ .bool = try self.nextBool() },
            .variant => return .{ .variant = try self.nextVariant() },
            .signature => return .{ .signature = try self.nextSignature() },
            .@"struct" => return .{ .@"struct" = try self.nextStruct() },
            .kv => return .{ .kv = try self.nextKv() },
            .array => return .{ .array = try self.nextArray() },
        }
    }

    pub fn nextTyped(self: *BodyReader, comptime T: type) !T {
        return self.nextTypedInner(T, 0);
    }

    pub fn nextTypedInner(self: *BodyReader, comptime T: type, depth: usize) !T {
        const typ = comptime DbusType.fromType(T);

        if (typ == .@"struct" and depth == 0) {
            return self.nextStructTyped(T, depth + 1);
        }

        var val = try self.next() orelse return makeDbusParseError(
            self.tokenizer.diagnostics,
            &self.reader.reader,
            error.ParseError,
            "unexpected end of body",
            .{},
        );

        if (val != typ) return makeDbusParseError(
            self.tokenizer.diagnostics,
            &self.reader.reader,
            error.InvalidType,
            "expected type {t} did not match found type {t}",
            .{ typ, val },
        );

        switch (typ) {
            inline .f64,
            .u32,
            .u64,
            .i32,
            .i64,
            .byte,
            .bool,
            .string,
            .object,
            .signature,
            => |t| return @field(val, @tagName(t)),
            inline .variant, .array => |t| return .{ .inner = @field(val, @tagName(t)) },
            inline .kv, .@"struct" => |t| {
                return @field(val, @tagName(t)).nextStructTyped(T, depth + 1);
            },
        }
    }

    fn nextStructTyped(self: *BodyReader, comptime T: type, depth: usize) !T {
        var ret: T = undefined;
        inline for (std.meta.fields(T)) |f| {
            @field(ret, f.name) = try self.nextTypedInner(f.type, depth + 1);
        }
        return ret;
    }

    fn convertError(self: *BodyReader, comptime T: type, val: anyerror!T) ParseError!T {
        return val catch |e| {
            return makeDbusParseError(
                self.tokenizer.diagnostics,
                &self.reader.reader,
                e,
                "failed to read {s} value",
                .{@typeName(T)},
            );
        };
    }

    pub fn nextF64(self: *BodyReader) ParseError!f64 {
        try self.nextCommon(.f64);
        return self.convertError(
            f64,
            self.reader.readF64(self.endianness),
        );
    }

    pub fn nextU64(self: *BodyReader) !u64 {
        try self.nextCommon(.u64);
        return self.convertError(
            u64,
            self.reader.readU64(self.endianness),
        );
    }

    pub fn nextU32(self: *BodyReader) !u32 {
        try self.nextCommon(.u32);
        return self.convertError(
            u32,
            self.reader.readU32(self.endianness),
        );
    }

    pub fn nextI64(self: *BodyReader) !i64 {
        try self.nextCommon(.i64);
        return self.convertError(
            i64,
            self.reader.readI64(self.endianness),
        );
    }

    pub fn nextByte(self: *BodyReader) !u8 {
        try self.nextCommon(.byte);
        return self.convertError(
            u8,
            self.reader.readByte(),
        );
    }

    pub fn nextI32(self: *BodyReader) !i32 {
        try self.nextCommon(.i32);
        return self.convertError(
            i32,
            self.reader.readI32(self.endianness),
        );
    }

    pub fn nextObject(self: *BodyReader) !DbusObject {
        try self.nextCommon(.object);
        return self.convertError(
            DbusObject,
            .{ .inner = try self.reader.readStringLike(self.endianness) },
        );
    }

    pub fn nextString(self: *BodyReader) !DbusString {
        try self.nextCommon(.string);
        return self.convertError(DbusString, .{ .inner = try self.reader.readStringLike(self.endianness) });
    }

    pub fn nextBool(self: *BodyReader) !bool {
        try self.nextCommon(.bool);
        return self.convertError(
            bool,
            self.reader.readBool(self.endianness),
        );
    }

    pub fn nextVariant(self: *BodyReader) !BodyReader {
        try self.nextCommon(.variant);
        return self.convertError(
            BodyReader,
            (try self.reader.readVariant(self.endianness, null)).inner,
        );
    }

    pub fn nextSignature(self: *BodyReader) !DbusSignature {
        try self.nextCommon(.signature);
        return .{ .inner = try self.reader.readSignature() };
    }

    pub fn nextStruct(self: *BodyReader) !BodyReader {
        try self.nextCommon(.struct_start);
        return self.convertError(
            BodyReader,
            self.reader.readStruct(&self.tokenizer, self.endianness, null),
        );
    }

    pub fn nextKv(self: *BodyReader) !BodyReader {
        try self.nextCommon(.kv_start);
        return self.convertError(
            BodyReader,
            self.reader.readStruct(&self.tokenizer, self.endianness, null),
        );
    }

    pub fn nextArray(self: *BodyReader) !ParseArrayUntyped {
        try self.nextCommon(.array_start);
        return self.convertError(
            ParseArrayUntyped,
            self.reader.readArray(&self.tokenizer, self.endianness, null),
        );
    }

    pub fn nextCommon(self: *BodyReader, expected_type: SignatureTokenizer.Token) !void {
        const token = try self.tokenizer.next() orelse return makeDbusParseError(
            self.tokenizer.diagnostics,
            &self.reader.reader,
            error.NoToken,
            "type fully consumed",
            .{},
        );

        if (token != expected_type) return makeDbusParseError(
            self.tokenizer.diagnostics,
            &self.reader.reader,
            error.InvalidType,
            "expected type {t} did not match found type {t}",
            .{ token, expected_type },
        );
    }
};

test "BodyReader struct" {
    var body_buf: [4096]u8 = undefined;
    var bs: BodySerializer = undefined;
    bs.initPinned(&body_buf, "(id(us))");

    try bs.startStruct();
    {
        try bs.addI32(0x1234);
        try bs.addDouble(1.234);

        try bs.startStruct();
        {
            try bs.addU32(0x1234);
            try bs.addString("hello");
        }
        try bs.endStruct();
    }
    try bs.endStruct();

    try std.testing.expectEqualStrings("(id(us))", bs.type_string.items);

    var br = BodyReader.init(
        bs.type_string.items,
        bs.body.writer.buffered(),
        .little,
        .{},
    );

    var outer_struct = try br.nextStruct();

    try std.testing.expectEqual(0x1234, try outer_struct.nextI32());
    try std.testing.expectEqual(1.234, try outer_struct.nextF64());

    var inner_struct = try outer_struct.nextStruct();
    try std.testing.expectEqual(0x1234, try inner_struct.nextU32());
    try std.testing.expectEqualStrings("hello", (try inner_struct.nextString()).inner);
}

test "BodyReader kv" {
    var body_buf: [4096]u8 = undefined;
    var bs: BodySerializer = undefined;
    bs.initPinned(&body_buf, "{i{us}}");

    try bs.startKv();
    {
        try bs.addI32(0x1234);
        try bs.startKv();
        {
            try bs.addU32(0x1234);
            try bs.addString("hello");
        }
        try bs.endKv();
    }
    try bs.endKv();

    try std.testing.expectEqualStrings("{i{us}}", bs.type_string.items);

    var br = BodyReader.init(
        bs.type_string.items,
        bs.body.writer.buffered(),
        .little,
        .{},
    );

    var outer_struct = try br.nextKv();

    try std.testing.expectEqual(0x1234, try outer_struct.nextI32());

    var inner_struct = try outer_struct.nextKv();
    try std.testing.expectEqual(0x1234, try inner_struct.nextU32());
    try std.testing.expectEqualStrings("hello", (try inner_struct.nextString()).inner);
}

test "BodyReader map" {
    var body_buf: [4096]u8 = undefined;
    var bs: BodySerializer = undefined;
    bs.initPinned(&body_buf, "a{iu}");

    try bs.startArray();
    for (0..5) |i| {
        try bs.startArrayElem();

        try bs.startKv();
        {
            try bs.addI32(@intCast(i * 2));
            try bs.addU32(@intCast(i * 4));
        }
        try bs.endKv();
    }
    try bs.endArray();

    try std.testing.expectEqualStrings("a{iu}", bs.type_string.items);

    var br = BodyReader.init(
        bs.type_string.items,
        bs.body.writer.buffered(),
        .little,
        .{},
    );

    var arr = try br.nextArray();

    try std.testing.expectEqualStrings("{iu}", arr.br.tokenizer.reader.buffered());

    var i: usize = 0;

    while (arr.next()) |arr_r| {
        var kv = try arr_r.nextKv();

        const key = try kv.nextI32();
        try std.testing.expectEqual(@as(i32, @intCast(i * 2)), key);
        const val = try kv.nextU32();

        try std.testing.expectEqual(@as(u32, @intCast(i * 4)), val);
        i += 1;
    }

    try std.testing.expectEqual(i, 5);
}

// Given a type signature and a body, helper to consume a single chunk of bytes
// that represents a single ParseValue
const ParseValueConsumer = struct {
    tokenizer: *SignatureTokenizer,
    tag_stack: TagParserStack,
    reader: *DbusMessageReader,
    diagnostics: ?*DbusErrorDiagnostics,

    pub fn initPinned(self: *ParseValueConsumer, tokenizer: *SignatureTokenizer, dbus_reader: *DbusMessageReader, diagnostics: ?*DbusErrorDiagnostics) void {
        self.* = .{
            .tokenizer = tokenizer,
            .tag_stack = undefined,
            .reader = dbus_reader,
            .diagnostics = diagnostics,
        };

        self.tag_stack.initPinned();
    }
    pub fn nextToken(self: *ParseValueConsumer) !?SignatureTokenizer.Token {
        return self.tokenizer.next();
    }

    pub fn handleToken(self: *ParseValueConsumer, token: SignatureTokenizer.Token, endianness: DbusEndianness) !void {
        const in_array = self.tag_stack.inArray();

        self.tag_stack.handleToken(token) catch |e| switch (e) {
            error.OutOfMemory, error.InvalidSignature => {
                return makeDbusParseError(
                    self.diagnostics,
                    &self.tokenizer.reader,
                    e,
                    "invalid signature",
                    .{},
                );
            },
        };

        if (!in_array) switch (token) {
            .array_start => {
                const len_bytes = try self.reader.readU32(endianness);
                const next_token = try self.tokenizer.peek() orelse {
                    return makeDbusParseError(
                        self.diagnostics,
                        &self.tokenizer.reader,
                        error.InvalidArraySignature,
                        "signature missing array type",
                        .{},
                    );
                };

                const t = DbusType.fromToken(next_token) catch {
                    return makeDbusParseError(
                        self.diagnostics,
                        &self.tokenizer.reader,
                        error.InvalidArraySignature,
                        "{t} is not a valid array type",
                        .{next_token},
                    );
                };

                try self.reader.alignForwards(alignmentOf(t));
                try self.reader.discard(len_bytes);
            },
            .kv_start, .struct_start => {
                try self.reader.alignForwards(alignmentOf(.@"struct"));
            },
            .bool, .u32, .i32 => {
                _ = try self.reader.readU32(endianness);
            },
            .u64, .i64, .f64 => {
                _ = try self.reader.readI64(endianness);
            },
            .object, .string => {
                _ = try self.reader.readStringLike(endianness);
            },
            .variant => {
                _ = try self.reader.readVariant(endianness, self.diagnostics);
            },
            .signature => {
                _ = try self.reader.readSignature();
            },
            else => {},
        };
    }
};

const TagParserStack = struct {
    buf: [10]Tag,
    stack: std.ArrayList(Tag),

    pub fn initPinned(self: *TagParserStack) void {
        self.buf = undefined;
        self.stack = std.ArrayList(Tag).initBuffer(&self.buf);
    }

    fn inArray(self: *const TagParserStack) bool {
        for (self.stack.items) |t| {
            if (t == .array) return true;
        }

        return false;
    }

    fn handleToken(self: *TagParserStack, token: SignatureTokenizer.Token) !void {
        switch (token) {
            .array_start => try self.stack.appendBounded(.array),
            .kv_start, .struct_start => try self.stack.appendBounded(.@"struct"),
            .struct_end, .kv_end => {
                const last_tag = self.stack.pop();
                if (last_tag != .@"struct") return error.InvalidSignature;
            },
            .byte, .u32, .u64, .i32, .i64, .f64, .object, .string, .bool, .variant, .signature => {},
        }

        try self.maybeEndArray(token);
    }

    fn maybeEndArray(self: *TagParserStack, token: SignatureTokenizer.Token) !void {
        switch (token) {
            .byte, .struct_end, .kv_end, .bool, .u32, .i32, .u64, .i64, .f64, .object, .string, .signature, .variant => {
                const t = self.stack.getLastOrNull() orelse return;
                if (t == .array) {
                    _ = self.stack.pop();
                }
            },
            .struct_start, .kv_start, .array_start => {},
        }
    }

    const Tag = enum {
        array,
        @"struct",
    };
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
    inner: BodyReader,
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
    dbus_reader: DbusMessageReader,

    pub fn next(self: *HeaderIt, options: ParseOptions) ParseError!?HeaderField {
        if (self.dbus_reader.reader.seek == self.dbus_reader.reader.buffer.len) {
            return null;
        }

        try self.dbus_reader.alignForwards(alignmentOf(.kv));
        const header_field_byte = try self.dbus_reader.readByte();
        const header_field = std.enums.fromInt(HeaderFieldTag, header_field_byte) orelse {
            return makeDbusParseError(
                options.diagnostics,
                &self.dbus_reader.reader,
                error.InvalidHeaderField,
                "{c} is not a valid header field",
                .{header_field_byte},
            );
        };

        var vr: BodyReader = .{
            .tokenizer = .{
                .diagnostics = null,
                .reader = .fixed("v"),
            },
            .reader = self.dbus_reader,
            .endianness = self.endianness,
        };

        var v = try vr.nextVariant();

        self.dbus_reader = vr.reader;

        switch (header_field) {
            .path => return .{ .path = try v.nextObject() },
            .interface => return .{ .interface = try v.nextString() },
            .member => return .{ .member = try v.nextString() },
            .error_name => return .{ .error_name = try v.nextString() },
            .reply_serial => return .{ .reply_serial = try v.nextU32() },
            .destination => return .{ .destination = try v.nextString() },
            .sender => return .{ .sender = try v.nextString() },
            .signature => return .{ .signature = try v.nextSignature() },
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
        var dbus_reader = DbusMessageReader{
            .reader = .fixed(buf),
        };

        const endianness_byte = try dbus_reader.readByte();
        const endianness = std.enums.fromInt(DbusEndianness, endianness_byte) orelse {
            return makeDbusParseError(
                diagnostics,
                &dbus_reader.reader,
                error.InvalidEndianness,
                "{c} is not a valid dbus endianness",
                .{endianness_byte},
            );
        };
        const message_type_byte = try dbus_reader.readByte();
        const message_type = std.enums.fromInt(MsgType, message_type_byte) orelse {
            return makeDbusParseError(
                diagnostics,
                &dbus_reader.reader,
                error.InvalidMessageType,
                "{d} is not a valid dbus message type",
                .{message_type_byte},
            );
        };
        const flags = try dbus_reader.readByte();
        const version_byte = try dbus_reader.readByte();
        const major_version = std.enums.fromInt(DBusVersion, version_byte) orelse {
            return makeDbusParseError(
                diagnostics,
                &dbus_reader.reader,
                error.InvalidVersion,
                "{d} is not a valid dbus version",
                .{version_byte},
            );
        };
        const body_len = try dbus_reader.readU32(endianness);
        const serial = try dbus_reader.readU32(endianness);

        const header_field_len = try dbus_reader.readU32(endianness);

        try dbus_reader.alignForwards(alignmentOf(.kv));

        const header_buf = try dbus_reader.readBytes(header_field_len);
        var header_it = HeaderIt{
            .endianness = endianness,
            .dbus_reader = .{ .reader = std.Io.Reader.fixed(header_buf) },
        };

        var headers = Headers{};
        while (try header_it.next(.{ .diagnostics = diagnostics })) |f| switch (f) {
            inline else => |v, t| {
                @field(headers, @tagName(t)) = v;
            },
        };

        try dbus_reader.alignForwards(body_alignment);
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

    pub fn call(serial: u32, path: []const u8, destination: []const u8, interface: []const u8, member: []const u8, body: *const BodySerializer, field_buf: []HeaderField) !DbusHeader {
        var header_fields = std.ArrayList(HeaderField).initBuffer(field_buf);
        try header_fields.appendSliceBounded(&.{
            .{ .path = .{ .inner = path } },
            .{ .destination = .{ .inner = destination } },
            .{ .interface = .{ .inner = interface } },
            .{ .member = .{ .inner = member } },
        });

        try appendBodySignature(&header_fields, body);

        return .{
            .endianness = .little,
            .message_type = .call,
            .flags = 0,
            .major_version = .@"1",
            .body_len = bodyLen(body),
            .serial = serial,
            .header_fields = header_fields.items,
        };
    }

    pub fn ret(serial: u32, reply_serial: u32, destination: []const u8, body: *const BodySerializer, field_buf: []HeaderField) !DbusHeader {
        var header_fields = std.ArrayList(HeaderField).initBuffer(field_buf);
        try header_fields.appendSliceBounded(&.{
            .{ .destination = .{ .inner = destination } },
            .{ .reply_serial = reply_serial },
        });

        try appendBodySignature(&header_fields, body);

        return .{
            .endianness = .little,
            .message_type = .ret,
            .flags = 0,
            .major_version = .@"1",
            .body_len = bodyLen(body),
            .serial = serial,
            .header_fields = header_fields.items,
        };
    }

    pub fn err(serial: u32, reply_serial: u32, destination: []const u8, err_name: DbusString, body: *const BodySerializer, field_buf: []HeaderField) !DbusHeader {
        var header_fields = std.ArrayList(HeaderField).initBuffer(field_buf);
        try header_fields.appendSliceBounded(&.{
            .{ .destination = .{ .inner = destination } },
            .{ .error_name = err_name },
            .{ .reply_serial = reply_serial },
        });

        try appendBodySignature(&header_fields, body);

        return .{
            .endianness = .little,
            .message_type = .err,
            .flags = 0,
            .major_version = .@"1",
            .body_len = bodyLen(body),
            .serial = serial,
            .header_fields = header_fields.items,
        };
    }

    pub fn signal(serial: u32, path: []const u8, interface: []const u8, member: []const u8, body: *const BodySerializer, field_buf: []HeaderField) !DbusHeader {
        var header_fields = std.ArrayList(HeaderField).initBuffer(field_buf);
        try header_fields.appendSliceBounded(&.{
            .{ .path = .{ .inner = path } },
            .{ .interface = .{ .inner = interface } },
            .{ .member = .{ .inner = member } },
        });

        try appendBodySignature(&header_fields, body);

        return .{
            .endianness = .little,
            .message_type = .signal,
            .flags = 0,
            .major_version = .@"1",
            .body_len = bodyLen(body),
            .serial = serial,
            .header_fields = header_fields.items,
        };
    }

    fn appendBodySignature(header_fields: *std.ArrayList(HeaderField), body: *const BodySerializer) !void {
        if (body.type_string.items.len == 0) return;
        try header_fields.appendBounded(.{
            .signature = .{ .inner = body.type_string.items },
        });
    }

    fn bodyLen(body: *const BodySerializer) u32 {
        return body.body.pos;
    }

    fn serialize(self: DbusHeader, io_writer: *std.Io.Writer, body: *const BodySerializer) SerializeError!void {
        // We don't handle this below I don't think
        std.debug.assert(self.endianness == .little);

        var w = DbusMessageWriter{
            .pos = 0,
            .writer = io_writer,
        };

        try w.writeByte(@intFromEnum(self.endianness));
        try w.writeByte(@intFromEnum(self.message_type));
        try w.writeByte(self.flags);
        try w.writeByte(@intFromEnum(self.major_version));

        try w.writeU32(self.body_len);
        try w.writeU32(self.serial);

        var header_buf: [4096]u8 = undefined;
        var header_field_io = std.Io.Writer.fixed(&header_buf);
        var header_field_writer = DbusMessageWriter{
            .pos = w.pos + 4,
            .writer = &header_field_io,
        };

        for (self.header_fields) |header_field| {
            try header_field_writer.alignForwards(alignmentOf(.kv));
            try header_field_writer.writeByte(@intFromEnum(header_field));
            try writeHeaderFieldVariant(&header_field_writer, header_field);
        }

        try w.writeU32(header_field_writer.pos - w.pos - 4); // num headers
        try w.writeAll(header_field_writer.writer.buffered());

        try w.alignForwards(body_alignment);

        try io_writer.writeAll(body.writer.buffered());
    }

    fn writeHeaderFieldVariant(w: *DbusMessageWriter, field: HeaderField) SerializeError!void {
        switch (field) {
            .path => |v| {
                try w.writeSignatureBytes("o");
                try w.writeStringLike(v.inner);
            },
            .interface, .member, .error_name, .destination, .sender => |v| {
                try w.writeSignatureBytes("s");
                try w.writeStringLike(v.inner);
            },
            .reply_serial => |v| {
                try w.writeSignatureBytes("u");
                try w.writeU32(v);
            },
            .signature => |v| {
                try w.writeSignatureBytes("g");
                try w.writeSignatureBytes(v.inner);
            },
        }
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
            switch (f) {
                inline else => |val, t| {
                    switch (@typeInfo(@TypeOf(val))) {
                        .@"struct" => {
                            try w.print("    {t}: {f}\n", .{ t, val });
                        },
                        .int => {
                            try w.print("    {t}: {d}\n", .{ t, val });
                        },
                        .@"enum" => {
                            try w.print("    {t}: {t}\n", .{ t, val });
                        },
                        else => comptime unreachable,
                    }
                },
            }
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
        try io_writer.print("AUTH EXTERNAL {f}\r\n", .{AuthUidFormatter{ .uid = std.os.linux.getuid() }});
        try io_writer.flush();

        return .{
            .state = .wait_for_ok,
        };
    }

    fn poll(self: *DbusConnectionInitializer, io_reader: *std.Io.Reader, io_writer: *std.Io.Writer) PollError!bool {
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
                var empty_body: BodySerializer = undefined;
                empty_body.initPinned(&.{}, "");
                hello_message.serialize(io_writer, &empty_body) catch {
                    return error.Unrecoverable;
                };
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

test "invalid array len crash" {
    var body_buf: [4096]u8 = undefined;
    var body: BodySerializer = undefined;
    body.initPinned(&body_buf, "au");

    try body.startArray();
    for (1..6) |i| {
        try body.startArrayElem();
        try body.addU32(@intCast(i));
    }
    try body.endArray();

    const msg = body.writer.buffered();

    // 5 elems, 4 bytes per elem, first 4 bytes is size
    std.debug.assert(std.mem.eql(u8, msg[0..4], &.{ 20, 0, 0, 0 }));

    // Lie about the size to make sure that we can process invalid data
    body_buf[0] = 25;

    var br = BodyReader.init(
        body.type_string.items,
        body.writer.buffered(),
        .little,
        .{},
    );
    try std.testing.expectError(error.ParseError, br.nextTyped(ParseArray(u32)));
}

pub const ParseError = error{ParseError} || std.Io.Reader.Error;
pub const SerializeError = error{SerializeError} || std.Io.Writer.Error;

pub const PollError = error{
    Unrecoverable,
} || ParseError || std.Io.Writer.Error;

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

    pub fn reset(self: *DbusErrorDiagnostics) void {
        self.error_reason = null;
        self.parse_context = &.{};
        self.error_pos = 0;
        self.message_len = 0;
    }

    pub fn message(self: DbusErrorDiagnostics) []const u8 {
        return self.message_buf[0..self.message_len];
    }

    // FIXME: Hexdump like visualization of packet for diagnostics. Maybe this
    // should be a sphtud thing
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

pub const BodySerializer = struct {
    writer: std.Io.Writer,
    body: DbusMessageWriter,

    type_string_buf: [255]u8,
    type_string: std.ArrayList(u8),

    arr_stack_buf: [256]ArrStackItem,
    arr_stack: std.ArrayList(ArrStackItem),
    type_string_compare_cursor: usize,

    variant_depth: u8,

    const ArrStackItem = struct {
        size: *[4]u8,
        type_start: usize,
        data_start: ?usize,
        tag_state: enum {
            initializing,
            writing,
            comparing,
        },
    };

    pub fn initPinned(self: *BodySerializer, buf: []u8, sig: []const u8) void {
        _ = sig;
        self.writer = std.Io.Writer.fixed(buf);
        self.body = .{
            .pos = 0,
            .writer = &self.writer,
        };
        self.type_string = .initBuffer(&self.type_string_buf);
        self.arr_stack = .initBuffer(&self.arr_stack_buf);
        self.type_string_compare_cursor = 0;
        self.variant_depth = 0;
    }

    pub fn addTyped(self: *BodySerializer, val: anytype) !void {
        try self.addTypedInner(val, 0);
    }

    fn addTypedInner(self: *BodySerializer, val: anytype, depth: usize) !void {
        const typ = comptime DbusType.fromType(@TypeOf(val));
        switch (typ) {
            .byte => try self.addByte(val),
            .bool => try self.addBool(val),
            .u32 => try self.addU32(val),
            .u64 => try self.addU64(val),
            .i32 => try self.addI32(val),
            .i64 => try self.addI64(val),
            .f64 => try self.addF64(val),
            .string => try self.addString(val.inner),
            .object => try self.addObject(val.inner),
            .signature => try self.addSignature(val.inner),
            .variant => {
                const sig = generateDbusSignature(@TypeOf(val.inner));

                try self.startVariant(sig);
                try self.addTyped(val.inner);
                try self.endVariant();
            },
            .kv => {
                try self.startKv();
                try self.addTyped(val.key, depth + 1);
                try self.addTyped(val.val, depth + 1);
                try self.endKv();
            },
            .@"struct" => {
                if (depth != 0) try self.startStruct();
                inline for (std.meta.fields(@TypeOf(val))) |f| {
                    try self.addTyped(@field(val, f.name));
                }
                if (depth != 0) try self.endStruct();
            },
            .array => {
                try self.startArray();
                for (val) |elem| {
                    try self.addTyped(elem, depth + 1);
                }
                try self.endArray();
            },
        }
    }

    pub fn addString(self: *BodySerializer, s: []const u8) !void {
        try self.commonStart(.string);
        try self.body.writeStringLike(s);
    }

    pub fn addObject(self: *BodySerializer, s: []const u8) !void {
        try self.commonStart(.object);
        try self.body.writeStringLike(s);
    }

    pub fn addSignature(self: *BodySerializer, sig: []const u8) !void {
        try self.commonStart(.signature);
        try self.body.writeSignatureBytes(sig);
    }

    pub fn addF64(self: *BodySerializer, val: f64) !void {
        try self.commonStart(.f64);
        try self.body.writeF64(val);
    }

    pub fn addI64(self: *BodySerializer, val: i64) !void {
        try self.commonStart(.i64);
        try self.body.writeI64(val);
    }

    pub fn addU64(self: *BodySerializer, val: u64) !void {
        try self.commonStart(.u64);
        try self.body.writeU64(val);
    }

    pub fn addI32(self: *BodySerializer, val: i32) !void {
        try self.commonStart(.i32);
        try self.body.writeI32(val);
    }

    pub fn addU32(self: *BodySerializer, val: u32) !void {
        try self.commonStart(.u32);
        try self.body.writeU32(val);
    }

    pub fn addBool(self: *BodySerializer, val: bool) !void {
        try self.commonStart(.bool);
        try self.body.writeBool(val);
    }

    pub fn addDouble(self: *BodySerializer, val: f64) !void {
        try self.commonStart(.f64);
        try self.body.writeF64(val);
    }

    pub fn addByte(self: *BodySerializer, val: u8) !void {
        try self.commonStart(.byte);
        try self.body.writeByte(val);
    }

    pub fn startStruct(self: *BodySerializer) !void {
        try self.commonStart(.@"struct");
    }

    pub fn endStruct(self: *BodySerializer) !void {
        try self.addTypeString(')');
    }

    pub fn startKv(self: *BodySerializer) !void {
        try self.commonStart(.kv);
    }

    pub fn endKv(self: *BodySerializer) !void {
        try self.addTypeString('}');
    }

    pub fn startVariant(self: *BodySerializer, sig: []const u8) !void {
        try self.commonStart(.variant);
        try self.body.writeSignatureBytes(sig);
        self.variant_depth += 1;
    }

    pub fn endVariant(self: *BodySerializer) !void {
        if (self.variant_depth == 0) return error.NoVariant;
        self.variant_depth -= 1;
    }

    fn commonStart(self: *BodySerializer, t: DbusType) !void {
        try self.addTypeString(t.typeString());

        if (self.getArrStackEnd()) |a| {
            if (a.data_start == null) {
                // If we are the first array element, ensure we are aligned
                // correctly and mark where the first element started for the
                // length calculation later
                try self.body.alignForwards(alignmentOf(t));
                a.data_start = self.writer.end;
            }
        } else {
            try self.body.alignForwards(alignmentOf(t));
        }
    }

    pub fn startArray(self: *BodySerializer) !void {
        try self.commonStart(.array);

        const size_ptr = try self.stubArrayLength();

        var new_arr_stack = ArrStackItem{
            .size = size_ptr,
            .data_start = null,
            .type_start = self.type_string.items.len,
            .tag_state = .initializing,
        };

        if (self.arr_stack.getLastOrNull()) |data| {
            if (data.tag_state == .comparing) {
                // If we are on the second element of an array, we are no
                // longer filling in the type info. If we have nested arrays we
                // need to respect that we are in the second iteration of some
                // array, even if we are in the first iteration of our own.
                // Here the type start/type_string_compare_cursor are no longer
                // just at the end, but where we inserted the type data last time

                self.type_string_compare_cursor = data.type_start;
                new_arr_stack.type_start = self.type_string_compare_cursor + 1;
                new_arr_stack.tag_state = .comparing;
            }
        }

        try self.arr_stack.appendBounded(new_arr_stack);
    }

    fn stubArrayLength(self: *BodySerializer) !*[4]u8 {
        try self.body.writeU32(0);
        const current_buffered = self.writer.buffered();
        return current_buffered[current_buffered.len - 4 ..][0..4];
    }

    pub fn endArray(self: *BodySerializer) !void {
        const data = self.arr_stack.pop() orelse return error.NoArray;
        const size_u32 = std.math.cast(u32, self.writer.end - data.data_start.?) orelse return error.ArrayTooLong;
        @memcpy(data.size, std.mem.asBytes(&size_u32));
    }

    pub fn startArrayElem(self: *BodySerializer) !void {
        const data = self.getArrStackEnd() orelse return error.NoArray;

        self.type_string_compare_cursor = data.type_start;

        switch (data.tag_state) {
            .initializing => data.tag_state = .writing,
            .writing => data.tag_state = .comparing,
            .comparing => {},
        }
    }

    fn getArrStackEnd(self: *BodySerializer) ?*ArrStackItem {
        if (self.arr_stack.items.len == 0) return null;
        return &self.arr_stack.items[self.arr_stack.items.len - 1];
    }

    fn addTypeString(self: *BodySerializer, val: u8) !void {
        // Inside a variant the inner type is carried in the body (as a
        // signature header) rather than in the outer signature, so we don't
        // touch type_string or the array comparison cursor at all.
        if (self.variant_depth > 0) return;

        const data = self.arr_stack.getLastOrNull() orelse {
            try self.type_string.appendBounded(val);
            return;
        };

        switch (data.tag_state) {
            .initializing => return error.SerializeError,
            .writing => {
                try self.type_string.appendBounded(val);
            },
            .comparing => {
                if (self.type_string_compare_cursor >= self.type_string.items.len) return error.SerializeError;
                if (self.type_string.items[self.type_string_compare_cursor] != val) return error.SerializeError;
                self.type_string_compare_cursor += 1;
            },
        }
    }

    test "single string" {
        var body_buf: [4096]u8 = undefined;
        var body: BodySerializer = undefined;
        body.initPinned(&body_buf, "s");

        try body.addString("hello");

        try std.testing.expectEqualStrings(body.type_string.items, "s");

        const data = body.writer.buffered();
        try std.testing.expectEqual(std.mem.readInt(u32, data[0..4], .little), "hello".len);
        try std.testing.expectEqualStrings(data[4..], "hello" ++ &[1]u8{0});
    }

    test "structure" {
        var body_buf: [4096]u8 = undefined;
        var body: BodySerializer = undefined;
        body.initPinned(&body_buf, "(xdy)");

        try body.startStruct();
        try body.addI64(0xcafef00d);
        try body.addDouble(1.234);
        try body.addByte('d');
        try body.endStruct();

        try std.testing.expectEqualStrings(body.type_string.items, "(xdy)");

        const data = body.writer.buffered();
        try std.testing.expectEqual(std.mem.readInt(i64, data[0..8], .little), 0xcafef00d);
        try std.testing.expectEqual(@as(f64, @bitCast(std.mem.readInt(i64, data[8..16], .little))), 1.234);
        try std.testing.expectEqual(data[16], 'd');
        try std.testing.expectEqual(data.len, 17);
    }

    test "variant primitive" {
        var body_buf: [4096]u8 = undefined;
        var body: BodySerializer = undefined;
        body.initPinned(&body_buf, "sv");

        try body.addString("org.example.Foo");
        try body.startVariant("d");
        try body.addDouble(1.0);
        try body.endVariant();

        try std.testing.expectEqualStrings("sv", body.type_string.items);
        try std.testing.expectEqual(0, body.variant_depth);
    }

    test "mismatched array elems" {
        var body_buf: [4096]u8 = undefined;
        var body: BodySerializer = undefined;
        body.initPinned(&body_buf, "au");

        try body.startArray();
        try body.startArrayElem();
        try body.addU32(1);
        try body.startArrayElem();
        try std.testing.expectError(error.SerializeError, body.addString("nope"));
    }

    test "end array without start" {
        var body_buf: [4096]u8 = undefined;
        var body: BodySerializer = undefined;
        body.initPinned(&body_buf, "");

        try std.testing.expectError(error.NoArray, body.endArray());
    }
};

pub const DbusConnection = struct {
    serial: u32,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    state: union(enum) {
        initializing: DbusConnectionInitializer,
        ready,
    },

    const Self = @This();

    pub fn init(reader: *std.Io.Reader, writer: *std.Io.Writer) !DbusConnection {
        return .{
            .reader = reader,
            .writer = writer,
            .serial = 2,
            .state = .{
                .initializing = try DbusConnectionInitializer.init(writer),
            },
        };
    }

    pub fn call(self: *Self, path: []const u8, destination: []const u8, interface: []const u8, member: []const u8, body: *const BodySerializer) !CallHandle {
        return try self.send(.{
            .call = .{
                .path = path,
                .destination = destination,
                .interface = interface,
                .member = member,
            },
        }, body);
    }

    pub fn ret(self: *DbusConnection, reply_serial: u32, destination: []const u8, body: *const BodySerializer) !void {
        _ = try self.send(.{
            .ret = .{
                .reply_serial = reply_serial,
                .destination = destination,
            },
        }, body);
    }

    pub fn err(self: *DbusConnection, reply_serial: u32, destination: []const u8, err_name: DbusString, body: *const BodySerializer) !void {
        _ = try self.send(.{
            .err = .{
                .reply_serial = reply_serial,
                .destination = destination,
                .err_name = err_name,
            },
        }, body);
    }

    pub fn signal(self: *DbusConnection, path: []const u8, interface: []const u8, member: []const u8, body: *const BodySerializer) !void {
        _ = try self.send(.{
            .signal = .{
                .path = path,
                .interface = interface,
                .member = member,
            },
        }, body);
    }

    const SendKind = union(enum) {
        call: struct {
            path: []const u8,
            destination: []const u8,
            interface: []const u8,
            member: []const u8,
        },
        ret: struct {
            reply_serial: u32,
            destination: []const u8,
        },
        err: struct {
            reply_serial: u32,
            destination: []const u8,
            err_name: DbusString,
        },
        signal: struct {
            path: []const u8,
            interface: []const u8,
            member: []const u8,
        },
    };

    fn send(self: *Self, kind: SendKind, body: *const BodySerializer) !CallHandle {
        if (self.state != .ready) return error.Uninitialized;

        var field_buf: [6]HeaderField = undefined;
        const to_send = switch (kind) {
            .call => |k| try DbusHeader.call(self.serial, k.path, k.destination, k.interface, k.member, body, &field_buf),
            .ret => |k| try DbusHeader.ret(self.serial, k.reply_serial, k.destination, body, &field_buf),
            .err => |k| try DbusHeader.err(self.serial, k.reply_serial, k.destination, k.err_name, body, &field_buf),
            .signal => |k| try DbusHeader.signal(self.serial, k.path, k.interface, k.member, body, &field_buf),
        };

        const handle = CallHandle{ .inner = self.serial };
        // We shouldn't have an outstanding request from 2^32 requests ago
        self.serial +%= 1;

        try to_send.serialize(self.writer, body);
        try self.writer.flush();

        return handle;
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

    fn pollReady(self: *Self, options: ParseOptions) PollError!Response {
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

    pub fn format(self: DbusObject, w: *std.Io.Writer) !void {
        try w.print("{s}", .{self.inner});
    }
};

pub const DbusString = struct {
    inner: []const u8,

    pub fn format(self: DbusString, w: *std.Io.Writer) !void {
        try w.print("{s}", .{self.inner});
    }
};

pub const DbusSignature = struct {
    inner: []const u8,

    pub fn format(self: DbusSignature, w: *std.Io.Writer) !void {
        try w.print("{s}", .{self.inner});
    }
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

        inner: ParseArrayUntyped,

        pub fn next(self: *@This()) !?Val {
            var elem = self.inner.next() orelse return null;
            return try elem.nextTyped(Val);
        }
    };
}

fn generateDbusSignatureInner(comptime T: type, sig: *std.ArrayList(u8)) !void {
    const t = comptime DbusType.fromType(T);
    switch (t) {
        .byte, .bool, .variant, .u32, .u64, .i32, .i64, .f64, .string, .object, .signature => try sig.appendBounded(t.typeString()),
        .array => {
            try sig.appendBounded(t.typeString());
            const ti = @typeInfo(T);
            try generateDbusSignatureInner(ti.pointer.child, sig);
        },
        .kv, .@"struct" => {
            const wants_struct_type = sig.items.len > 0;

            if (wants_struct_type) try sig.appendBounded(t.typeString());

            for (std.meta.fields(T)) |field| {
                try generateDbusSignatureInner(field.type, sig);
            }

            const end = if (t == .kv) '}' else ')';
            if (wants_struct_type) try sig.appendBounded(end);
        },
    }
}

pub fn generateDbusSignature(comptime T: type) []const u8 {
    return comptime blk: {
        var sig_buf: [255]u8 = undefined;
        var sig = std.ArrayList(u8).initBuffer(&sig_buf);
        generateDbusSignatureInner(T, &sig) catch unreachable;
        const final = sig.items[0..sig.items.len].*;
        break :blk &final;
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

        self.connection = try DbusConnection.init(&self.tx_reader.interface, &self.rx.writer);

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

    var body_buf: [4096]u8 = undefined;
    _ = try interface.playPause(&body_buf);

    // Strace play pause from qdbus on spotify
    const play_pause_message = "\x6c\x01\x00\x01\x00\x00\x00\x00\x02\x00\x00\x00\x82\x00\x00\x00\x01\x01\x6f\x00\x17\x00\x00\x00\x2f\x6f\x72\x67\x2f\x6d\x70\x72\x69\x73\x2f\x4d\x65\x64\x69\x61\x50\x6c\x61\x79\x65\x72\x32\x00\x06\x01\x73\x00\x1e\x00\x00\x00\x6f\x72\x67\x2e\x6d\x70\x72\x69\x73\x2e\x4d\x65\x64\x69\x61\x50\x6c\x61\x79\x65\x72\x32\x2e\x73\x70\x6f\x74\x69\x66\x79\x00\x00\x02\x01\x73\x00\x1d\x00\x00\x00\x6f\x72\x67\x2e\x6d\x70\x72\x69\x73\x2e\x4d\x65\x64\x69\x61\x50\x6c\x61\x79\x65\x72\x32\x2e\x50\x6c\x61\x79\x65\x72\x00\x00\x00\x03\x01\x73\x00\x09\x00\x00\x00\x50\x6c\x61\x79\x50\x61\x75\x73\x65\x00\x00\x00\x00\x00\x00\x00";
    try std.testing.expectEqualSlices(u8, play_pause_message, try fixture.rx_reader.interface.take(play_pause_message.len));

    // Property retrieval
    {
        var buf: [4096]u8 = undefined;
        const volume_handle = try interface.getVolume(&buf);

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
        var buf: [4096]u8 = undefined;
        try interface.setVolumeProperty(&buf, 1.0);

        // Traced from a working interaction
        const expected_volume_req = .{ 108, 1, 0, 1, 64, 0, 0, 0, 4, 0, 0, 0, 137, 0, 0, 0, 1, 1, 111, 0, 23, 0, 0, 0, 47, 111, 114, 103, 47, 109, 112, 114, 105, 115, 47, 77, 101, 100, 105, 97, 80, 108, 97, 121, 101, 114, 50, 0, 6, 1, 115, 0, 30, 0, 0, 0, 111, 114, 103, 46, 109, 112, 114, 105, 115, 46, 77, 101, 100, 105, 97, 80, 108, 97, 121, 101, 114, 50, 46, 115, 112, 111, 116, 105, 102, 121, 0, 0, 2, 1, 115, 0, 31, 0, 0, 0, 111, 114, 103, 46, 102, 114, 101, 101, 100, 101, 115, 107, 116, 111, 112, 46, 68, 66, 117, 115, 46, 80, 114, 111, 112, 101, 114, 116, 105, 101, 115, 0, 3, 1, 115, 0, 3, 0, 0, 0, 83, 101, 116, 0, 0, 0, 0, 0, 8, 1, 103, 0, 3, 115, 115, 118, 0, 0, 0, 0, 0, 0, 0, 0, 29, 0, 0, 0, 111, 114, 103, 46, 109, 112, 114, 105, 115, 46, 77, 101, 100, 105, 97, 80, 108, 97, 121, 101, 114, 50, 46, 80, 108, 97, 121, 101, 114, 0, 0, 0, 6, 0, 0, 0, 86, 111, 108, 117, 109, 101, 0, 1, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 240, 63 };
        try std.testing.expectEqualSlices(u8, &expected_volume_req, try fixture.rx_reader.interface.take(expected_volume_req.len));
    }
}

test {
    std.testing.refAllDecls(@This());
}
