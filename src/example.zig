const std = @import("std");
const sphtud = @import("sphtud");
const builtin = @import("builtin");
const dbus = @import("sphdbus");
const mpris = @import("mpris");

fn onVolumeRetrieved(ctx: ?*anyopaque, response: f64) !void {
    const running: *bool = @ptrCast(@alignCast(ctx));
    std.debug.print("volume: {d}\n", .{response});
    running.* = false;
}

const GetMessageParams = struct {
    interface_name: dbus.DbusString,
    property_name: dbus.DbusString,
};

pub fn main() !void {
    var alloc_buf: [1 * 1024 * 1024]u8 = undefined;
    var buf_alloc = sphtud.alloc.BufAllocator.init(&alloc_buf);

    const alloc = buf_alloc.allocator();
    const scratch = buf_alloc.backLinear();

    const OnInitialized = struct {
        running: *bool,

        pub fn notify(ctx: @This(), connection: anytype, writer: *std.Io.Writer) !void {
            const player = mpris.OrgMprisMediaPlayer2Player.interface(connection, "org.mpris.MediaPlayer2.spotify", "/org/mpris/MediaPlayer2");
            try player.getVolume(
                writer,
                ctx.running,
                onVolumeRetrieved,
            );
        }
    };

    var running: bool = true;
    var loop = try sphtud.event.LoopLinear.init(
        alloc,
        alloc,
    );

    var connection = try dbus.dbusConnectionHandler(sphtud.event.LoopLinear, alloc, scratch, OnInitialized{ .running = &running });

    try loop.register(connection.handler());

    const cp = scratch.checkpoint();
    while (running) {
        scratch.restore(cp);
        try loop.wait(scratch);
    }
}
