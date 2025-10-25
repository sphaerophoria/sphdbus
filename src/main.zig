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
        std.debug.print("prop: {s}, {any}\n", .{ prop.key.inner, prop.val });
    }
}

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

    const OnInitialized = struct {
        pub fn notify(_: @This(), connection: anytype, writer: *std.Io.Writer) !void {
            const player = mpris.OrgMprisMediaPlayer2Player.interface(connection, "org.mpris.MediaPlayer2.spotify", "/org/mpris/MediaPlayer2");
            try player.getVolume(
                writer,
                null,
                onVolumeRetrieved,
            );
        }
    };

    var connection = try dbus.dbusConnectionHandler(sphtud.event.LoopLinear, alloc, &scratch, socket, OnInitialized{});

    var loop = try sphtud.event.LoopLinear.init(
        alloc,
        alloc,
    );
    try loop.register(connection.handler());

    const cp = scratch.checkpoint();
    while (true) {
        scratch.restore(cp);
        try loop.wait(scratch.linear());
    }
}
