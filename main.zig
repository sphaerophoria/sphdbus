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
    signature: SignatureTag,
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
            .signature => |v| try writer.print("{t}" ,.{v}),
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

const Message = struct {
    endianness: DbusEndianness,
    message_type: MsgType,
    flags: u8,
    major_version: DBusVersion,
    body_len: u32,
    serial: u32,
    header_fields: []const HeaderFieldKV,
    body: DbusVal,

    fn parse(alloc: std.mem.Allocator, io_reader: *std.Io.Reader) !Message {
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

        var body_signature = SignatureTag.empty;

        while (dbus_reader.pos < end_header_pos) {
            try dbus_reader.alignForwards(8);
            const header_field_byte = try dbus_reader.readByte();
            const header_field = std.meta.intToEnum(HeaderField, header_field_byte) catch return error.InvalidHeaderField;
            const signature_len = try dbus_reader.readByte();
            const signature = try parseSignature(try dbus_reader.readBytes(signature_len + 1));

            switch (signature) {
                .empty, .byte => {
                    unreachable;
                },
                .string => {
                    const string_len = try dbus_reader.readU32(endianness);
                    const s = try dbus_reader.readBytes(string_len);
                    try headers_tmp.appendBounded(.{
                        .typ = header_field,
                        .val = .{ .string = try alloc.dupe(u8, s)},
                    });
                    _ = try dbus_reader.readByte();
                },
                // FIXME: Copy paste with string wtf
                .object => {
                    const string_len = try dbus_reader.readU32(endianness);
                    const s = try dbus_reader.readBytes(string_len);
                    try headers_tmp.appendBounded(.{
                        .typ = header_field,
                        .val = .{ .object = try alloc.dupe(u8, s)},
                    });
                    _ = try dbus_reader.readByte();
                },
                .signature => {
                    const string_len = try dbus_reader.readByte();
                    const s = try dbus_reader.readBytes(string_len + 1);
                    try headers_tmp.appendBounded(.{
                        .typ = header_field,
                        .val = .{ .signature = try parseSignature(s)},
                    });
                },
                .u32 => {
                    const val = try dbus_reader.readU32(endianness);
                    try headers_tmp.appendBounded(.{
                        .typ = header_field,
                        .val = .{ .u32 = val },
                    });
                },
                .i64 => {
                    const val = try dbus_reader.readI64(endianness);
                    try headers_tmp.appendBounded(.{
                        .typ = header_field,
                        .val = .{ .i64 = val },
                    });

                },
                .unknown => {
                    try headers_tmp.appendBounded(.{
                        .typ = header_field,
                        .val = .unknown,
                    });

                },

            }

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

        var body: DbusVal = .empty;
        switch (body_signature) {
            .empty => {
                if (body_len != 0) return error.InvalidBody;
            },
            .string => {
                const s_len = try dbus_reader.readU32(endianness);
                const s = try dbus_reader.readBytes(s_len);
                body = .{ .string = try alloc.dupe(u8, s) };
                _ = try dbus_reader.readByte();
            },
            .i64 => {
                body = .{ .i64 = try dbus_reader.readI64(endianness) };
            },
            else => {
                io_reader.toss(body_len);
                std.log.err("Unhandled signature {t}\n", .{body_signature});
            },
        }

        return .{
            .endianness = endianness,
            .message_type = message_type,
            .flags = flags,
            .major_version = major_version,
            .body_len = body_len,
            .serial = serial,
            .header_fields = try alloc.dupe(HeaderFieldKV, headers_tmp.items),
            .body = body,
        };

    }

    pub fn call(serial: u32, path: []const u8, destionation: []const u8, interface: []const u8, member: []const u8, body: DbusVal, field_buf: []HeaderFieldKV) !Message {
        const body_len = body.size();

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

        switch (body) {
            .empty => {},
            else => {
                try header_fields.appendBounded(.{
                    .typ = .signature,
                    .val = .{ .signature = body },
                });
            },

        }

        return Message {
            .endianness = .little,
            .message_type = .call,
            .flags = 0, // FIXME: Might have to have flags sometimes
            .major_version = .@"1",
            .body_len = body_len,
            .serial = serial,
            .header_fields = header_fields.items,
            .body = body,
        };
    }

    fn serialize(self: Message, io_writer: *std.Io.Writer) !void {
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
                    try header_field_writer.writeVariantTag(v.tag());
                },
                else => unreachable,
            }
        }

        try w.writeU32(header_field_writer.pos - w.pos - 4); // num headers
        try w.writeAll(header_field_writer.writer.buffered());
        try w.alignForwards(8); // body alignment

        switch (self.body) {
            .i64 => |v| try w.writeI64(v),
            .empty => {},
            else => unreachable,
        }
    }

    pub fn format(self: Message, w: *std.Io.Writer) !void {
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
            try w.print("body: {f}\n" ,.{self.body});
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

                const hello_message = Message {
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
                    .body = .empty,
                };
                try hello_message.serialize(io_writer);
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
        onFinish: *const fn(ctx: ?*anyopaque, val: DbusVal) void,
    };

    fn onFinish(self: CompletionHandler, val: DbusVal) void {
        self.vtable.onFinish(self.ctx, val);
    }
};

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

        pub fn call(self: *Self, path: []const u8, destionation: []const u8, interface: []const u8, member: []const u8, body: DbusVal, on_finish: ?CompletionHandler) !void {

            var field_buf: [6]HeaderFieldKV = undefined;
            const to_send = try Message.call(
                self.serial,
                path,
                destionation,
                interface,
                member,
                body,
                 &field_buf,
            );
            self.serial += 1;

            std.debug.print("Sending\n {f}\n", .{to_send});
            try to_send.serialize(&self.writer.interface);
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
                // Message.parse in a way where it doesn't consume bytes from
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

                    const message = Message.parse(self.scratch.allocator(), &tmp_reader) catch |e| switch (e) {
                        error.EndOfStream => break,
                        else => return e,
                    };
                    std.debug.print("{f}\n", .{message});

                    io_reader.toss(tmp_reader.seek);

                    if (self.outstanding_requests.get(message.serial)) |h| {
                        h.onFinish(message.body);
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

fn onPlayFinished(ctx: ?*anyopaque, _: DbusVal) void {
    const connection: *DbusConnection(sphtud.event.LoopLinear) = @ptrCast(@alignCast(ctx));
    connection.call(
        "/org/mpris/MediaPlayer2",
         "org.mpris.MediaPlayer2.spotify",
         "org.mpris.MediaPlayer2.Player",
         "Seek",
         .{ .i64 = -10000000 },
         null,
    ) catch unreachable;
}

const msg = "\x6c\x01\x00\x01\x00\x00\x00\x00\x05\x00\x00\x00\x81\x00\x00\x00\x01\x01\x6f\x00\x17\x00\x00\x00\x2f\x6f\x72\x67\x2f\x6d\x70\x72\x69\x73\x2f\x4d\x65\x64\x69\x61\x50\x6c\x61\x79\x65\x72\x32\x00\x06\x01\x73\x00\x1e\x00\x00\x00\x6f\x72\x67\x2e\x6d\x70\x72\x69\x73\x2e\x4d\x65\x64\x69\x61\x50\x6c\x61\x79\x65\x72\x32\x2e\x73\x70\x6f\x74\x69\x66\x79\x00\x00\x02\x01\x73\x00\x1d\x00\x00\x00\x6f\x72\x67\x2e\x6d\x70\x72\x69\x73\x2e\x4d\x65\x64\x69\x61\x50\x6c\x61\x79\x65\x72\x32\x2e\x50\x6c\x61\x79\x65\x72\x00\x00\x00\x03\x01\x73\x00\x08\x00\x00\x00\x50\x6f\x73\x69\x74\x69\x6f\x6e\x00\x00\x00\x00\x00\x00\x00\x00";


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

    const parsed = try Message.parse(scratch.allocator(), &msg_reader);
    std.debug.print("{f}\n", .{parsed});

    //var wbuf: [4096]u8 = undefined;
    //var buf_writer = std.Io.Writer.fixed(&wbuf);
    //var field_buf: [6]HeaderFieldKV = undefined;
    //const out = try Message.call(
    //    5,
    //    "/org/mpris/MediaPlayer2",
    //     "org.mpris.MediaPlayer2.spotify",
    //     "org.mpris.MediaPlayer2.Player",
    //     "Position",
    //     .empty,
    //     &field_buf,
    //);
    //try out.serialize(&buf_writer);

    //std.debug.assert(std.mem.eql(u8, buf_writer.buffered(), msg));
    std.debug.print("{any}\n", .{msg});
    //std.debug.print("{any}\n", .{buf_writer.buffered()});


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
                 .empty,
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

