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
};

const MsgType = enum (u8) {
    call = 1,
};


const DBusVersion = enum(u8) {
    @"1" = 1,
};

const HeaderField = enum(u8) {
    path = 1,
    interface = 2,
    member = 3,
    destination = 6,
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

fn serializeHelloMsg(w: *DbusWriter) !void {
    try w.writeByte(@intFromEnum(DbusEndianness.little));
    try w.writeByte(@intFromEnum(MsgType.call));
    try w.writeByte(0); // flags
    try w.writeByte(@intFromEnum(DBusVersion.@"1"));

    try w.writeU32(0); // len
    try w.writeU32(1); // serial

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

    try io_reader.fillMore();
    std.debug.print("response {s}\n", .{io_reader.buffered()});

}
