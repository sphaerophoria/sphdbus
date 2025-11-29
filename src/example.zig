const std = @import("std");
const sphtud = @import("sphtud");
const builtin = @import("builtin");
const dbus = @import("sphdbus");
const mpris = @import("mpris");

const DbusHandler = struct {
    connection: dbus.DbusConnection,
    state: union(enum) {
        wait_initialize,
        wait_volume: dbus.DbusConnection.CallHandle,
    },

    pub fn init(alloc: std.mem.Allocator) !DbusHandler {
        const stream = try dbus.sessionBus();

        const reader = try alloc.create(std.net.Stream.Reader);
        reader.* = stream.reader(try alloc.alloc(u8, 4096));

        const writer = try alloc.create(std.net.Stream.Writer);
        writer.* = stream.writer(try alloc.alloc(u8, 4096));

        const connection = try dbus.dbusConnection(reader.interface(), &writer.interface);

        return .{
            .connection = connection,
            .state = .wait_initialize,
        };
    }

    fn poll(self: *DbusHandler) !void {
        while (true) {
            const res = try self.connection.poll();

            const player = mpris.OrgMprisMediaPlayer2Player {
                .connection = &self.connection,
                .service = "org.mpris.MediaPlayer2.spotify",
                .object_path = "/org/mpris/MediaPlayer2",
            };

            switch (self.state) {
                .wait_initialize => {
                    if (res == .initialized) {
                        self.state = .{ .wait_volume =  try player.getVolume() };
                    }
                },
                .wait_volume => |wait_for| {
                    if (res != .response) continue;
                    if (res.response.handle.inner != wait_for.inner) continue;

                    const parsed = try mpris.OrgMprisMediaPlayer2Player.parseGetVolumeResponse(
                        res.response.header,
                    );

                    try player.setVolumeProperty(parsed - 0.1);

                    return;
                },
            }
        }
    }

    fn close (ctx: ?*anyopaque) void {
        _ = ctx;
    }
};

pub fn main() !void {
    var alloc_buf: [1 * 1024 * 1024]u8 = undefined;
    var buf_alloc = sphtud.alloc.BufAllocator.init(&alloc_buf);

    const alloc = buf_alloc.allocator();

    var handler = try DbusHandler.init(alloc);
    try handler.poll();
}
