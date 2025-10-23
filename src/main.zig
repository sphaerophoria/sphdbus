const std = @import("std");
const sphtud = @import("sphtud");
const builtin = @import("builtin");
const dbus = @import("sphdbus");
const login1 = @import("login1");
const mpris = @import("mpris");

fn extractUnixPathFromAddress(address: []const u8) ![]const u8 {
    const tag = "unix:path=";
    if (!std.mem.startsWith(u8, address, tag)) return error.NotUnixPath;
    return address[tag.len..];
}

fn onUserRetrieved(_: ?*anyopaque, response: login1.OrgFreedesktopLogin1Manager.GetUserResponse) !void {
    std.debug.print("User object path: {s}\n", .{response.object_path.inner});
}

fn onCanSleep(_: ?*anyopaque, response: login1.OrgFreedesktopLogin1Manager.CanSleepResponse) !void {
    std.debug.print("Can sleep: {s}\n", .{response.result.inner});
}

fn onListUsers(_: ?*anyopaque, response: login1.OrgFreedesktopLogin1Manager.ListUsersResponse) !void {
    for (response.users) |user| {
        std.debug.print("user {d} {s}: {s}\n", .{ user[0], user[1].inner, user[2].inner });
    }
}

fn onVolumeRetrieved(_: ?*anyopaque, response: f64) !void {
    std.debug.print("volume: {d}\n", .{response});
}

fn onPropertiesRetrieved(_: ?*anyopaque, response: login1.OrgFreedesktopDBusProperties.GetAllResponse) !void {
    for (response.props) |prop| {
        std.debug.print("prop: {s}, {any}\n", .{prop.key.inner, prop.val});
    }
}

const msg = "\x6c\x01\x00\x01\x22\x00\x00\x00\x05\x00\x00\x00\x87\x00\x00\x00\x01\x01\x6f\x00\x17\x00\x00\x00\x2f\x6f\x72\x67\x2f\x6d\x70\x72\x69\x73\x2f\x4d\x65\x64\x69\x61\x50\x6c\x61\x79\x65\x72\x32\x00\x06\x01\x73\x00\x1e\x00\x00\x00\x6f\x72\x67\x2e\x6d\x70\x72\x69\x73\x2e\x4d\x65\x64\x69\x61\x50\x6c\x61\x79\x65\x72\x32\x2e\x73\x70\x6f\x74\x69\x66\x79\x00\x00\x02\x01\x73\x00\x1f\x00\x00\x00\x6f\x72\x67\x2e\x66\x72\x65\x65\x64\x65\x73\x6b\x74\x6f\x70\x2e\x44\x42\x75\x73\x2e\x50\x72\x6f\x70\x65\x72\x74\x69\x65\x73\x00\x03\x01\x73\x00\x06\x00\x00\x00\x47\x65\x74\x41\x6c\x6c\x00\x00\x08\x01\x67\x00\x01\x73\x00\x00\x1d\x00\x00\x00\x6f\x72\x67\x2e\x6d\x70\x72\x69\x73\x2e\x4d\x65\x64\x69\x61\x50\x6c\x61\x79\x65\x72\x32\x2e\x50\x6c\x61\x79\x65\x72\x00";

const mse = "\x6c\x01\x00\x01\x22\x00\x00\x00\x02\x00\x00\x00\x86\x00\x00\x00\x01\x01\x6f\x00\x17\x00\x00\x00\x2f\x6f\x72\x67\x2f\x6d\x70\x72\x69\x73\x2f\x4d\x65\x64\x69\x61\x50\x6c\x61\x79\x65\x72\x32\x00\x06\x01\x73\x00\x1e\x00\x00\x00\x6f\x72\x67\x2e\x6d\x70\x72\x69\x73\x2e\x4d\x65\x64\x69\x61\x50\x6c\x61\x79\x65\x72\x32\x2e\x73\x70\x6f\x74\x69\x66\x79\x00\x00\x02\x01\x73\x00\x1f\x00\x00\x00\x6f\x72\x67\x2e\x66\x72\x65\x65\x64\x65\x73\x6b\x74\x6f\x70\x2e\x44\x42\x75\x73\x2e\x50\x72\x6f\x70\x65\x72\x74\x69\x65\x73\x00\x03\x01\x73\x00\x06\x00\x00\x00\x47\x65\x74\x41\x6c\x6c\x00\x00\x08\x01\x67\x00\x00\x73\x00\x00\x1d\x00\x00\x00\x6f\x72\x67\x2e\x6d\x70\x72\x69\x73\x2e\x4d\x65\x64\x69\x61\x50\x6c\x61\x79\x65\x72\x32\x2e\x50\x6c\x61\x79\x65\x72\x00";

const GetMessageParams = struct {
    interface_name: dbus.DbusString,
    property_name: dbus.DbusString,
};

pub fn main() !void {
    var alloc_buf: [1 * 1024 * 1024]u8 = undefined;
    var buf_alloc = sphtud.alloc.BufAllocator.init(&alloc_buf);

    var scratch_buf: [1 * 1024 * 1024]u8 = undefined;
    var scratch = sphtud.alloc.BufAllocator.init(&scratch_buf);

    const alloc = buf_alloc.allocator();

    const session_address = std.posix.getenv("DBUS_SESSION_BUS_ADDRESS") orelse return error.NoSessionAddress;
    const socket_path = try extractUnixPathFromAddress(session_address);

    const socket = try std.net.connectUnixSocket(socket_path);

    var reader = socket.reader(try alloc.alloc(u8, 4096));
    var writer = socket.writer(try alloc.alloc(u8, 4096));

    var connection = try dbus.DbusConnection(sphtud.event.LoopLinear).init(alloc, &scratch, &reader, &writer);

    var msg_reader = std.Io.Reader.fixed(msg);

    const parsed = try dbus.DbusHeader.parse(scratch.allocator(), &msg_reader);
    std.debug.print("{f}\n", .{parsed});
    //const params = try dbus.dbusParseBody(GetMessageParams, alloc, scratch.linear(), parsed.endianness, try parsed.signature(), msg_reader.buffered());
    //std.debug.print("interface name: {s}\n", .{params.interface_name.inner});
    //std.debug.print("property name: {s}\n", .{params.property_name.inner});

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
    std.debug.print("{s}", .{dbus.generateDbusSignature(struct{
        dbus.DbusString,
        dbus.DbusString,
    })});

    //const manager = login1.OrgFreedesktopLogin1Manager.interface(&connection, "org.freedesktop.login1", "/org/freedesktop/login1");
    //const player = mpris.OrgMprisMediaPlayer2Player.interface(&connection, "org.mpris.MediaPlayer2.spotify", "/org/mpris/MediaPlayer2");
    const properties = login1.OrgFreedesktopDBusProperties.interface(&connection, "org.mpris.MediaPlayer2.spotify", "/org/mpris/MediaPlayer2");

    const cp = scratch.checkpoint();
    while (true) {
        scratch.restore(cp);
        try loop.wait(scratch.linear());

        if (!called and connection.state == .ready) {
            called = true;
            try properties.getAll(
                .{ .inner = "org.mpris.MediaPlayer2.Player" },
                null,
                onPropertiesRetrieved,
            );
        }
    }
}
