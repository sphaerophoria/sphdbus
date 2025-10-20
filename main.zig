const std = @import("std");
const sphtud = @import("sphtud");
const builtin = @import("builtin");

fn extractUnixPathFromAddress(address: []const u8) ![]const u8 {
    const tag = "unix:path=";
    if (!std.mem.startsWith(u8, address, tag)) return error.NotUnixPath;
    return address[tag.len..];
}

fn waitForStartsWith(reader: *std.Io.Reader, start: []const u8, err: anyerror) !void {
    const response = try reader.takeDelimiterInclusive('\n');
    if (!std.mem.startsWith(u8, response, start)) {
        return err;
    }
}

const DbusEndianness = enum (u8) {
    little = 'l',
    big = 'b',

    fn toBuiltin(self: DbusEndianness) std.builtin.Endian {
        return switch (self) {
            .little => return .little,
            .big => return .big,
        };
    }
};

const MsgType = enum (u8) {
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

    fn readVariant(self: *DbusMessageReader, alloc: std.mem.Allocator, endianness: DbusEndianness) !DbusVal {
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
                const ret = DbusVal{ .string = try alloc.dupe(u8, s)};
                _ = try self.readByte();
                return ret;
            },
            // FIXME: Copy paste with string wtf
            .object => {
                const string_len = try self.readU32(endianness);
                const s = try self.readBytes(string_len);
                const ret = DbusVal{ .object = try alloc.dupe(u8, s)};
                _ = try self.readByte();
                return ret;
            },
            .signature => {
                const string_len = try self.readByte();
                const s = try self.readBytes(string_len + 1);
                return DbusVal{ .signature = try alloc.dupe(u8, s)};
            },
            .u32 => {
                const val = try self.readU32(endianness);
                return .{ .u32 = val };
            },
            .i64 => {
                const val = try self.readI64(endianness);
                return .{ .i64 = val };
            },
            .unknown => {
                return .unknown;
            },
        }
    }
};

fn serializeHelloMsg(iow: *std.Io.Writer) !void {

    var w = DbusMessageWriter {
        .pos = 0,
        .writer = iow,
    };
    try w.writeByte(@intFromEnum(DbusEndianness.little));
    try w.writeByte(@intFromEnum(MsgType.call));
    try w.writeByte(0); // flags
    try w.writeByte(@intFromEnum(DBusVersion.@"1"));

    try w.writeU32(0); // len
    try w.writeU32(55); // serial

    var header_buf: [4096]u8 = undefined;
    var header_field_io = std.Io.Writer.fixed(&header_buf);
    var header_field_writer = DbusMessageWriter {
        .pos = w.pos + 4,
        .writer = &header_field_io,
    };

    try header_field_writer.alignForwards(8); // struct alignment
    try header_field_writer.writeByte(@intFromEnum(HeaderField.path));
    try header_field_writer.writeVariantTag("o");
    try header_field_writer.writeStringLike("/org/freedesktop/DBus");

    try header_field_writer.alignForwards(8); // struct alignment
    try header_field_writer.writeByte(@intFromEnum(HeaderField.destination));
    try header_field_writer.writeVariantTag("s");
    try header_field_writer.writeStringLike("org.freedesktop.DBus");

    try header_field_writer.alignForwards(8); // struct alignment
    try header_field_writer.writeByte(@intFromEnum(HeaderField.interface));
    try header_field_writer.writeVariantTag("s");
    try header_field_writer.writeStringLike("org.freedesktop.DBus");

    try header_field_writer.alignForwards(8); // struct alignment
    try header_field_writer.writeByte(@intFromEnum(HeaderField.member));
    try header_field_writer.writeVariantTag("s");
    try header_field_writer.writeStringLike("Hello");

    try w.writeU32(header_field_writer.pos - w.pos - 4); // num headers
    try w.writeAll(header_field_writer.writer.buffered());
    try w.alignForwards(8); // body alignment
}

const SignatureTag = enum {
    empty,
    byte,
    string,
    object,
    signature,
    u32,
    i64,
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
            .unknown => unreachable,
        };
    }
};

const DbusVal = union(SignatureTag) {
    empty,
    byte: u8,
    string: []const u8,
    object: []const u8,
    signature: []const u8,
    u32: u32,
    i64: i64,
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
            .byte => |v| try writer.print("{d}" ,.{v}),
            .string => |v| try writer.print("{s}" ,.{v}),
            .object => |v| try writer.print("{s}" ,.{v}),
            .signature => |v| try writer.print("{s}" ,.{v}),
            .u32 => |v| try writer.print("{d}" ,.{v}),
            .i64 => |v| try writer.print("{d}" ,.{v}),
            .unknown => try writer.print("unknown", .{}) ,
        }
    }
};

fn parseSignature(sig: []const u8) !SignatureTag {
    if (std.mem.eql(u8, "s\x00", sig)) return .string;
    if (std.mem.eql(u8, "u\x00", sig)) return .u32;
    if (std.mem.eql(u8, "g\x00", sig)) return .signature;
    if (std.mem.eql(u8, "o\x00", sig)) return .object;
    if (std.mem.eql(u8, "\x00", sig)) return .empty;
    if (std.mem.eql(u8, "x\x00", sig)) return .i64;
    std.log.err("Unimplemented signature: {s} (len {d})", .{sig, sig.len});
    return .unknown;
}

const HeaderFieldKV = struct {
    typ: HeaderField,
    val: DbusVal,
};

const DbusHeader = struct {
    endianness: DbusEndianness,
    message_type: MsgType,
    flags: u8,
    major_version: DBusVersion,
    body_len: u32,
    serial: u32,
    header_fields: []const HeaderFieldKV,

    fn parse(alloc: std.mem.Allocator, io_reader: *std.Io.Reader) !DbusHeader {
        var dbus_reader = DbusMessageReader {
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
                .val = .{ .signature = body_signature, },
            });
        }

        var discarding_writer = std.Io.Writer.Discarding.init(&.{});
        try dbusSerialize(&discarding_writer.writer, body);

        return DbusHeader {
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

        var w = DbusMessageWriter {
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
        var header_field_writer = DbusMessageWriter {
            .pos = w.pos + 4,
            .writer = &header_field_io,
        };

        for (self.header_fields) |header_field| {
            try header_field_writer.alignForwards(8); // struct alignment
            try header_field_writer.writeByte(@intFromEnum(header_field.typ));
            const tag = header_field.val.tag();
            try header_field_writer.writeVariantTag(tag);
            switch (header_field.val) {
                .string, .object => |v| try header_field_writer.writeStringLike(v),
                .signature => |v| {
                    try header_field_writer.writeByte(@intCast(v.len - 1));
                    try header_field_writer.writeAll(v);
                },
                else => unreachable,
            }
        }

        try w.writeU32(header_field_writer.pos - w.pos - 4); // num headers
        try w.writeAll(header_field_writer.writer.buffered());
        try w.alignForwards(8); // body alignment

        try dbusSerialize(w.writer, body);
    }

    pub fn format(self: DbusHeader, w: *std.Io.Writer) !void {
        try w.print("endianness: {}\n" ,.{self.endianness});
        try w.print("message_type: {}\n" ,.{self.message_type});
        try w.print("flags: {}\n" ,.{self.flags});
        try w.print("major_version: {}\n" ,.{self.major_version});
        try w.print("body_len: {}\n" ,.{self.body_len});
        try w.print("serial: {}\n" ,.{self.serial});

        try w.print("headers\n" ,.{});
        for (self.header_fields) |f| {
            try w.print("    {t}: {f}\n" ,.{f.typ, f.val});
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

                const hello_message = DbusHeader {
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

const CompletionHandler = struct {
    ctx: ?*anyopaque,
    vtable: *const VTable,

    const VTable = struct {
        onFinish: *const fn(ctx: ?*anyopaque, endianness: DbusEndianness, signature: []const u8, val: []const u8) void,
    };

    fn onFinish(self: CompletionHandler, endianness: DbusEndianness, signature: []const u8, val: []const u8) void {
        self.vtable.onFinish(self.ctx, endianness, signature, val);
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
    var dbus_writer = DbusMessageWriter {
        .pos = 0,
        .writer = io_writer,
    };

    return dbusSerializeInner(&dbus_writer, val);
}

fn dbusParseBody(comptime T: type, alloc: std.mem.Allocator, endianness: DbusEndianness, signature: []const u8, body: []const u8) !T {
    var reader = std.Io.Reader.fixed(body);

    if (!std.mem.eql(u8, signature, generateDbusSignature(T))) {
        return error.InvalidType;
    }

    try reader.fill(body.len);
    var body_reader = std.Io.Reader.fixed(reader.buffered());
    reader.toss(body.len);

    var dr = DbusMessageReader {
        .pos = 0,
        .reader = &body_reader,
    };

    var ret: T = undefined;
    inline for (std.meta.fields(T)) |field| {
        switch (field.type) {
            DbusObject, DbusString => {
                const string_len = try dr.readU32(endianness);
                // Known that string content lives in body, so it's ok
                const s = try dr.readBytes(string_len);
                _ = try dr.readBytes(1);

                @field(ret, field.name) = .{ .inner = s };
            },
            DbusVal => {
                @field(ret, field.name) = try dr.readVariant(alloc, endianness);

            },
            else => @compileError("Unsupported type " ++ @typeName(field.type)),
        }
    }

    return ret;
}

pub fn DbusConnection(comptime Loop: type) type {
    return struct {
        scratch: sphtud.alloc.LinearAllocator,
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


        pub fn init(alloc: std.mem.Allocator, scratch: sphtud.alloc.LinearAllocator, reader: *std.net.Stream.Reader, writer: *std.net.Stream.Writer) !Self {
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
                            h.onFinish(message.endianness, try message.signature(), body_buf);
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

fn onPropertyFinished(_: ?*anyopaque, endianness: DbusEndianness, signature: []const u8, body: []const u8) void {
    var tmp_buf: [4096]u8 = undefined;
    var scratch = sphtud.alloc.BufAllocator.init(&tmp_buf);
    std.debug.print("{any}\n", .{body});
    const val = dbusParseBody(struct { DbusVal }, scratch.allocator(), endianness, signature, body) catch unreachable;
    std.debug.print("Current play position: {f}\n", .{val[0]});
}

fn onPlayFinished(ctx: ?*anyopaque, _: DbusEndianness, _: []const u8, _: []const u8) void {
    const connection: *DbusConnection(sphtud.event.LoopLinear) = @ptrCast(@alignCast(ctx));
    connection.call(
        "/org/mpris/MediaPlayer2",
         "org.mpris.MediaPlayer2.spotify",
         "org.freedesktop.DBus.Properties",
         "Get",
         .{ DbusString { .inner = "org.mpris.MediaPlayer2.Player" }, DbusString { .inner = "Position" } },
         .{
             .ctx = null,
             .vtable = &.{
                 .onFinish = onPropertyFinished,
             },
         },
    ) catch unreachable;
}

const msg = "\x6c\x01\x00\x01\x31\x00\x00\x00\x07\x00\x00\x00\x88\x00\x00\x00\x01\x01\x6f\x00\x17\x00\x00\x00\x2f\x6f\x72\x67\x2f\x6d\x70\x72\x69\x73\x2f\x4d\x65\x64\x69\x61\x50\x6c\x61\x79\x65\x72\x32\x00\x06\x01\x73\x00\x1e\x00\x00\x00\x6f\x72\x67\x2e\x6d\x70\x72\x69\x73\x2e\x4d\x65\x64\x69\x61\x50\x6c\x61\x79\x65\x72\x32\x2e\x73\x70\x6f\x74\x69\x66\x79\x00\x00\x02\x01\x73\x00\x1f\x00\x00\x00\x6f\x72\x67\x2e\x66\x72\x65\x65\x64\x65\x73\x6b\x74\x6f\x70\x2e\x44\x42\x75\x73\x2e\x50\x72\x6f\x70\x65\x72\x74\x69\x65\x73\x00\x03\x01\x73\x00\x03\x00\x00\x00\x47\x65\x74\x00\x00\x00\x00\x00\x08\x01\x67\x00\x02\x73\x73\x00\x1d\x00\x00\x00\x6f\x72\x67\x2e\x6d\x70\x72\x69\x73\x2e\x4d\x65\x64\x69\x61\x50\x6c\x61\x79\x65\x72\x32\x2e\x50\x6c\x61\x79\x65\x72\x00\x00\x00\x08\x00\x00\x00\x50\x6f\x73\x69\x74\x69\x6f\x6e\x00";

const GetMessageParams = struct {
    interface_name: DbusString,
    property_name: DbusString,
};

const DbusObject = struct {
    inner: []const u8,
};

const DbusString = struct {
    inner: []const u8,
};

fn generateDbusSignature(comptime T: type) []const u8 {
    return comptime blk: {
        const fields = std.meta.fields(T);
        var ret: []const u8 = "";
        for (fields) |field| {
            ret = ret ++ switch (field.type) {
                DbusString => "s",
                DbusObject => "o",
                i64 => "x",
                u32 => "u",
                DbusVal => "v",
                else => @compileError("unimplemented for field type " ++ @typeName(field.type)),
            };
        }
        ret = ret ++ "\x00";
        break :blk ret;
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

pub fn main() !void {
    var alloc_buf: [1 * 1024 * 1024]u8 = undefined;
    var buf_alloc = sphtud.alloc.BufAllocator.init(&alloc_buf);

    const alloc = buf_alloc.allocator();
    const scratch = buf_alloc.backLinear();

    const session_address = std.posix.getenv("DBUS_SESSION_BUS_ADDRESS") orelse return error.NoSessionAddress;
    const socket_path = try extractUnixPathFromAddress(session_address);

    const socket = try std.net.connectUnixSocket(socket_path);

    var reader = socket.reader(try alloc.alloc(u8, 4096));
    var writer = socket.writer(try alloc.alloc(u8, 4096));

    var connection = try DbusConnection(sphtud.event.LoopLinear).init(alloc, scratch, &reader, &writer);

    var msg_reader = std.Io.Reader.fixed(msg);

    const parsed = try DbusHeader.parse(scratch.allocator(), &msg_reader);
    std.debug.print("{f}\n", .{parsed});
    const params = try dbusParseBody(GetMessageParams, scratch.allocator(), parsed.endianness, try parsed.signature(), msg_reader.buffered());
    std.debug.print("interface name: {s}\n", .{params.interface_name.inner});
    std.debug.print("property name: {s}\n", .{params.property_name.inner});

    var wbuf: [4096]u8 = undefined;
    var buf_writer = std.Io.Writer.fixed(&wbuf);
    var field_buf: [6]HeaderFieldKV = undefined;
    const body = .{ DbusString { .inner = "org.mpris.MediaPlayer2.Player" }, DbusString { .inner = "Position" } };
    const out = try DbusHeader.call(
        5,
        "/org/mpris/MediaPlayer2",
         "org.mpris.MediaPlayer2.spotify",
         "org.freedesktop.DBus.Properties",
         "Get",
         body,
         &field_buf,
    );
    try out.serialize(&buf_writer, body);

    //std.debug.assert(std.mem.eql(u8, buf_writer.buffered(), msg));
    std.debug.print("{any}\n", .{msg});
    std.debug.print("{any}\n", .{buf_writer.buffered()});


    // endianness: .little
    // message_type: .call
    // flags: 0
    // major_version: .1
    // body_len: 0
    // serial: 5
    // headers
    //     path: /org/mpris/MediaPlayer2
    //     destination: org.mpris.MediaPlayer2.spotify
    //     interface: org.mpris.MediaPlayer2.Player
    //     member: Play
    // body:

    var loop = try sphtud.event.LoopLinear.init(
        alloc,
        alloc,
    );
    try loop.register(connection.handler());

    var called = false;

    const cp = scratch.checkpoint();
    while (true) {
        scratch.restore(cp);
        try loop.wait(scratch);

        if (!called and connection.state == .ready) {
            called = true;
            try connection.call(
                "/org/mpris/MediaPlayer2",
                 "org.mpris.MediaPlayer2.spotify",
                 "org.mpris.MediaPlayer2.Player",
                 "Play",
                 .{},
                 .{
                     .ctx = &connection,
                     .vtable = &.{
                         .onFinish = onPlayFinished,
                     },
                 },
            );
        }

    }
}

