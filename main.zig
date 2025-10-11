const std = @import("std");
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


const DbusWriter = struct {
    pos: u32,
    writer: *std.Io.Writer,

    fn writeByte(self: *DbusWriter, b: u8) !void {
        try self.writer.writeByte(b);
        self.pos += 1;
    }

    fn writeU32(self: *DbusWriter, val: u32) !void {
        try self.alignForwards(4);
        try self.writer.writeInt(u32, val, builtin.cpu.arch.endian());
        self.pos += 4;
    }

    fn writeAll(self: *DbusWriter, data: []const u8) !void {
        const len_u32 = std.math.cast(u32, data.len) orelse return error.InvalidLen;
        try self.writer.writeAll(data);
        self.pos += len_u32;
    }

    fn writeVariantTag(self: *DbusWriter, tag: []const u8) !void {
        const tag_len_u8 = std.math.cast(u8, tag.len) orelse return error.InvalidLen;
        try self.writer.writeByte(tag_len_u8);
        self.pos += 1;

        try self.writer.writeAll(tag);
        self.pos += tag_len_u8;
    }

    fn writeStringLike(self: *DbusWriter, s: []const u8) !void {
        const s_len_u32 = std.math.cast(u32, s.len) orelse return error.InvalidLen;
        try self.writeU32(s_len_u32);

        try self.writer.writeAll(s);
        self.pos += s_len_u32;

        try self.writer.writeByte(0);
        self.pos += 1;
    }

    fn alignForwards(self: *DbusWriter, alignment: u32) !void {
        const new_pos = std.mem.alignForward(u32, self.pos, alignment);
        try self.writer.splatByteAll(0, new_pos - self.pos);
        self.pos = new_pos;
    }
};

const DbusReader = struct {
    pos: u32,
    reader: *std.Io.Reader,

    fn readByte(self: *DbusReader) !u8 {
        const ret = try self.reader.takeByte();
        self.pos += 1;
        return ret;
    }

    fn readBytes(self: *DbusReader, n: u32) ![]const u8 {
        const ret = try self.reader.take(n);
        self.pos += n;
        return ret;
    }

    fn readU32(self: *DbusReader, endianness: DbusEndianness) !u32 {
        try self.alignForwards(4);
        const ret = try self.reader.takeInt(u32, endianness.toBuiltin());
        self.pos += 4;
        return ret;
    }

    fn alignForwards(self: *DbusReader, alignment: u32) !void {
        const new_pos = std.mem.alignForward(u32, self.pos, alignment);
        try self.reader.discardAll(new_pos - self.pos);
        self.pos = new_pos;
    }
};

fn serializeHelloMsg(w: *DbusWriter) !void {
    try w.writeByte(@intFromEnum(DbusEndianness.little));
    try w.writeByte(@intFromEnum(MsgType.call));
    try w.writeByte(0); // flags
    try w.writeByte(@intFromEnum(DBusVersion.@"1"));

    try w.writeU32(0); // len
    try w.writeU32(55); // serial

    var header_buf: [4096]u8 = undefined;
    var header_field_io = std.Io.Writer.fixed(&header_buf);
    var header_field_writer = DbusWriter {
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
};

const DbusVal = union(SignatureTag) {
    empty,
    byte: u8,
    string: []const u8,
    object: []const u8,
    signature: SignatureTag,
    u32: u32,

    pub fn format(self: DbusVal, writer: *std.Io.Writer) !void {
        switch (self) {
            .empty => {},
            .byte => |v| try writer.print("{d}" ,.{v}),
            .string => |v| try writer.print("{s}" ,.{v}),
            .object => |v| try writer.print("{s}" ,.{v}),
            .signature => |v| try writer.print("{t}" ,.{v}),
            .u32 => |v| try writer.print("{d}" ,.{v}),
        }
    }
};

fn parseSignature(sig: []const u8) !SignatureTag {
    if (std.mem.eql(u8, "s\x00", sig)) return .string;
    if (std.mem.eql(u8, "u\x00", sig)) return .u32;
    if (std.mem.eql(u8, "g\x00", sig)) return .signature;
    if (std.mem.eql(u8, "o\x00", sig)) return .object;
    std.log.err("Unimplemented signature: {s}", .{sig});
    return error.Unimplemented;
}

const HeaderFieldKV = struct {
    typ: HeaderField,
    val: DbusVal,
};

const Header = struct {
    endianness: DbusEndianness,
    message_type: MsgType,
    flags: u8,
    major_version: DBusVersion,
    body_len: u32,
    serial: u32,
    header_fields: []HeaderFieldKV,
    body: DbusVal,

    fn parse(alloc: std.mem.Allocator, io_reader: *std.Io.Reader) !Header {
        var dbus_reader = DbusReader {
            .pos = 0,
            .reader = io_reader,
        };
        // peekUntilFromPos
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
            else => unreachable,
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

    pub fn format(self: Header, w: *std.Io.Writer) !void {
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


pub fn main() !void {
    const session_address = std.posix.getenv("DBUS_SESSION_BUS_ADDRESS") orelse return error.NoSessionAddress;
    const socket_path = try extractUnixPathFromAddress(session_address);

    const socket = try std.net.connectUnixSocket(socket_path);
    var reader_buf: [4096]u8 = undefined;
    var reader = socket.reader(&reader_buf);

    var writer_buf: [4096]u8 = undefined;
    var writer = socket.writer(&writer_buf);
    var io_writer = &writer.interface;

    try io_writer.writeByte(0);
    try io_writer.print("AUTH EXTERNAL 31303031\r\n", .{});
    try io_writer.flush();

    const io_reader: *std.Io.Reader = reader.interface();
    try waitForStartsWith(io_reader, "OK", error.NotOk);

    try io_writer.print("NEGOTIATE_UNIX_FD\r\n", .{});
    try io_writer.flush();
    try waitForStartsWith(io_reader, "AGREE_UNIX_FD", error.NoUnixFd);

    try io_writer.print("BEGIN\r\n", .{});
    try io_writer.flush();

    //var test_buf: [4096]u8 = undefined;
    //var test_buf_io = std.Io.Writer.fixed(&test_buf);
    var test_dbus_writer = DbusWriter {
        .pos = 0,
        .writer = io_writer,
    };

    try serializeHelloMsg(&test_dbus_writer);
    try io_writer.flush();

    var alloc_buf: [1 * 1024 * 1024]u8 = undefined;
    var alloc = std.heap.FixedBufferAllocator.init(&alloc_buf);

    while (true) {
        const header = try Header.parse(alloc.allocator(), io_reader);
        std.debug.print("{f}\n", .{header});
    }
}

