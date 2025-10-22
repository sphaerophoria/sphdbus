const std = @import("std");
const sphtud = @import("sphtud");
const builtin = @import("builtin");

fn waitForStartsWith(reader: *std.Io.Reader, start: []const u8, err: anyerror) !void {
    const response = try reader.takeDelimiterInclusive('\n');
    if (!std.mem.startsWith(u8, response, start)) {
        std.debug.print("{s} is not {s}\n", .{ response, start });
        return err;
    }
}

pub const SignatureTokenizer = struct {
    reader: *std.Io.Reader,

    pub const Token = enum {
        array_start,
        array_end,
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
            'a' => {
                const nb = (try self.takeByte()) orelse return error.InvalidArray;
                if (nb != '(') return error.InvalidArray;
                return .array_start;
            },
            ')' => return .array_end,
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

    fn writeVariant(self: *DbusMessageWriter, val: DbusVal) !void {
        const tag = val.tag();
        try self.writeVariantTag(tag);
        switch (val) {
            .string, .object => |v| try self.writeStringLike(v),
            .signature => |v| {
                try self.writeByte(@intCast(v.len - 1));
                try self.writeAll(v);
            },
            .f64 => |v| try self.writeF64(v),
            else => unreachable,
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

    fn readVariant(self: *DbusMessageReader, alloc: ?std.mem.Allocator, endianness: DbusEndianness) !DbusVal {
        if (alloc == null) {
            std.debug.assert(self.reader.vtable == std.Io.Reader.fixed(&.{}).vtable);
        }

        const signature_len = try self.readByte();
        std.debug.print("Reading sig of len {d}\n", .{signature_len});
        const signature = try parseSignature(try self.readBytes(signature_len + 1));

        switch (signature) {
            .empty, .byte => {
                unreachable;
            },
            .string => {
                const string_len = try self.readU32(endianness);
                const s = try self.readBytes(string_len);
                const ret = DbusVal{ .string = try dupeIfAlloc(alloc, u8, s) };
                _ = try self.readByte();
                return ret;
            },
            // FIXME: Copy paste with string wtf
            .object => {
                const string_len = try self.readU32(endianness);
                const s = try self.readBytes(string_len);
                const ret = DbusVal{ .object = try dupeIfAlloc(alloc, u8, s) };
                _ = try self.readByte();
                return ret;
            },
            .signature => {
                const string_len = try self.readByte();
                const s = try self.readBytes(string_len + 1);
                return DbusVal{ .signature = try dupeIfAlloc(alloc, u8, s) };
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
    signature,
    u32,
    i64,
    f64,
    unknown,

    pub fn tag(self: SignatureTag) []const u8 {
        return switch (self) {
            .empty => unreachable,
            .byte => "y",
            .string => "s",
            .object => "o",
            .signature => "g",
            .u32 => "u",
            .i64 => "x",
            .f64 => "d",
            .unknown => unreachable,
        };
    }
};

pub const DbusVal = union(SignatureTag) {
    empty,
    byte: u8,
    string: []const u8,
    object: []const u8,
    signature: []const u8,
    u32: u32,
    i64: i64,
    f64: f64,
    unknown,

    pub fn tag(self: DbusVal) []const u8 {
        return SignatureTag.tag(self);
    }
    pub fn size(self: DbusVal) u32 {
        return switch (self) {
            .empty => 0,
            .byte => 1,
            .string, .object => |s| @intCast(s.len + 4),
            .signature => @intCast(self.tag().len + 1), // FIXME: double check
            .u32 => 4,
            .i64 => 8,
            .unknown => unreachable,
        };
    }

    pub fn format(self: DbusVal, writer: *std.Io.Writer) !void {
        switch (self) {
            .empty => {},
            .byte => |v| try writer.print("{d}", .{v}),
            .string => |v| try writer.print("{s}", .{v}),
            .object => |v| try writer.print("{s}", .{v}),
            .signature => |v| try writer.print("{s}", .{v}),
            .u32 => |v| try writer.print("{d}", .{v}),
            .i64 => |v| try writer.print("{d}", .{v}),
            .f64 => |v| try writer.print("{d}", .{v}),
            .unknown => try writer.print("unknown", .{}),
        }
    }
};

//FIXME:  feels duplicated with something or otehr
fn parseSignature(sig: []const u8) !SignatureTag {
    if (std.mem.eql(u8, "s\x00", sig)) return .string;
    if (std.mem.eql(u8, "u\x00", sig)) return .u32;
    if (std.mem.eql(u8, "g\x00", sig)) return .signature;
    if (std.mem.eql(u8, "o\x00", sig)) return .object;
    if (std.mem.eql(u8, "\x00", sig)) return .empty;
    if (std.mem.eql(u8, "x\x00", sig)) return .i64;
    if (std.mem.eql(u8, "d\x00", sig)) return .f64;
    std.log.err("Unimplemented signature: {s} (len {d})", .{ sig, sig.len });
    return .unknown;
}

const HeaderFieldKV = struct {
    typ: HeaderField,
    val: DbusVal,
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

        if (body_signature.len > 1) {
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
            .flags = 0, // FIXME: Might have to have flags sometimes
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

    pub fn getHeader(self: DbusHeader, header: HeaderField) ?DbusVal {
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

pub const DbusConnectionInitializer = struct {
    state: enum {
        wait_for_ok,
        wait_for_ack,
        complete,
    },

    pub fn init(io_writer: *std.Io.Writer) !DbusConnectionInitializer {
        try io_writer.writeByte(0);
        // FIXME: Base off UID?
        try io_writer.print("AUTH EXTERNAL 31303031\r\n", .{});
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
        DbusVal => {
            try dbus_writer.writeVariant(val);
            return;
        },
        else => {},
    }

    switch (@typeInfo(@TypeOf(val))) {
        .@"struct" => |si| {
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
    var ret: T = undefined;
    inline for (std.meta.fields(T)) |field| {
        switch (@typeInfo(field.type)) {
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

                try dr.alignForwards(8);

                while (dr.pos < start + array_len_bytes) {
                    std.debug.print("at {d}, end at {d}\n", .{ dr.pos, start + array_len_bytes });
                    try builder.append(try dbusParseBodyInner(pi.child, alloc, scratch, endianness, dr));
                }

                @field(ret, field.name) = try builder.makeContiguous(alloc);
                continue;
            },
            else => {},
        }

        switch (field.type) {
            DbusObject, DbusString => {
                const string_len = try dr.readU32(endianness);
                std.debug.print("string len {d}\n", .{string_len});
                // Known that string content lives in body, so it's ok
                const s = try dr.readBytes(string_len);
                _ = try dr.readBytes(1);

                @field(ret, field.name) = .{ .inner = s };
            },
            DbusVal => {
                // Known that string content lives in body, so it's ok to not pass allocator
                @field(ret, field.name) = try dr.readVariant(null, endianness);
            },
            u32 => {
                @field(ret, field.name) = try dr.readU32(endianness);
            },
            f64 => {
                @field(ret, field.name) = try dr.readF64(endianness);
            },
            else => @compileError("Unsupported type " ++ @typeName(field.type)),
        }
    }

    return ret;
}

pub fn dbusParseBody(comptime T: type, alloc: std.mem.Allocator, scratch: sphtud.alloc.LinearAllocator, endianness: DbusEndianness, signature: []const u8, body: []const u8) !T {
    var reader = std.Io.Reader.fixed(body);

    if (!std.mem.eql(u8, signature, generateDbusSignature(T))) {
        std.debug.print("Expected {s} got {s}\n", .{ generateDbusSignature(T), signature });
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

pub fn DbusConnection(comptime Loop: type) type {
    return struct {
        scratch: *sphtud.alloc.BufAllocator,
        reader: *std.net.Stream.Reader,
        writer: *std.net.Stream.Writer,
        // FIXME: What happens when we wrap?
        serial: u32,
        state: union(enum) {
            initializing: DbusConnectionInitializer,
            ready,
        },
        outstanding_requests: sphtud.util.AutoHashMapLinear(u32, CompletionHandler),

        const Self = @This();

        pub fn init(alloc: std.mem.Allocator, scratch: *sphtud.alloc.BufAllocator, reader: *std.net.Stream.Reader, writer: *std.net.Stream.Writer) !Self {
            try sphtud.event.setNonblock(reader.getStream().handle);

            return .{
                .scratch = scratch,
                .writer = writer,
                .reader = reader,
                .serial = 2,
                .state = .{
                    .initializing = try DbusConnectionInitializer.init(&writer.interface),
                },
                .outstanding_requests = try .init(
                    alloc,
                    alloc,
                    16,
                    1024,
                ),
            };
        }

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
                body, // FIXME: Really looks like body ends up in message
                &field_buf,
            );
            self.serial += 1;

            std.debug.print("Sending\n {f}\n", .{to_send});
            try to_send.serialize(&self.writer.interface, body);
            try self.writer.interface.flush();

            if (on_finish) |h| {
                std.debug.print("Injecting handler for {d}\n", .{to_send.serial});
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

                    std.debug.print("Received {s}\n", .{io_reader.buffered()});

                    const message = DbusHeader.parse(self.scratch.allocator(), &tmp_reader) catch |e| switch (e) {
                        error.EndOfStream => break,
                        else => return e,
                    };

                    const body_buf = try self.scratch.allocator().alloc(u8, message.body_len);
                    _ = try tmp_reader.readSliceAll(body_buf);
                    std.debug.print("{f}\n", .{message});

                    io_reader.toss(tmp_reader.seek);

                    var it = self.outstanding_requests.iter();
                    while (it.next()) |i| {
                        std.debug.print("Have handler for for {d}\n", .{i.key.*});
                    }

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

fn generateDbusSignatureInner(comptime T: type) []const u8 {
    const fields = std.meta.fields(T);
    var ret: []const u8 = "";
    for (fields) |field| {
        switch (@typeInfo(field.type)) {
            .pointer => |pi| {
                std.debug.assert(pi.size == .slice);

                ret = ret ++ "a(" ++ generateDbusSignatureInner(pi.child) ++ ")";
                continue;
            },
            else => {},
        }

        ret = ret ++ switch (field.type) {
            DbusString => "s",
            DbusObject => "o",
            i64 => "x",
            u32 => "u",
            DbusVal => "v",
            f64 => "d",
            else => @compileError("unimplemented for field type " ++ @typeName(field.type)),
        };
    }
    return ret;
}

fn generateDbusSignature(comptime T: type) []const u8 {
    return comptime blk: {
        const ret = generateDbusSignatureInner(T);
        break :blk ret ++ "\x00";
    };
}

test "dbus sig gen" {
    const s = generateDbusSignature(struct {
        x: DbusString,
        y: DbusObject,
        i: i64,
        u: u32,
    });

    try std.testing.expectEqualStrings("soxu\x00", s);
}
