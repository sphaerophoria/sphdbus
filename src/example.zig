const std = @import("std");
const sphtud = @import("sphtud");
const builtin = @import("builtin");
const dbus = @import("sphdbus");
const mpris = @import("mpris");

const DbusHandler = struct {
    connection: dbus.DbusConnection,
    stream: std.posix.fd_t,
    state: union(enum) {
        wait_initialize,
        wait_volume: dbus.CallHandle,
    },

    pub fn init(alloc: std.mem.Allocator, env: std.process.Environ) !DbusHandler {
        const bus_path = try dbus.sessionBusPath(env);

        const system = sphtud.io.system;
        const stream = try sphtud.io.socket(system.AF.UNIX, system.SOCK.STREAM, 0);
        try sphtud.io.connectUnix(stream, try .init(bus_path));

        try sphtud.io.setBlockMode(stream, .block);

        const reader = try alloc.create(sphtud.io.Reader);
        reader.* = sphtud.io.Reader.init(stream, try alloc.alloc(u8, 4096));

        const writer = try alloc.create(sphtud.io.Writer);
        writer.* = sphtud.io.Writer.init(stream, try alloc.alloc(u8, 4096));

        const connection = try dbus.DbusConnection.init(&reader.interface, &writer.interface);

        return .{
            .stream = stream,
            .connection = connection,
            .state = .wait_initialize,
        };
    }

    pub fn deinit(self: *DbusHandler) void {
        sphtud.io.close(self.stream);
    }

    fn poll(self: *DbusHandler, options: dbus.ParseOptions) !void {
        while (true) {
            const res = try self.connection.poll(options);

            const player = mpris.OrgMprisMediaPlayer2Player{
                .connection = &self.connection,
                .service = "org.mpris.MediaPlayer2.spotify",
                .object_path = "/org/mpris/MediaPlayer2",
            };

            switch (self.state) {
                .wait_initialize => {
                    if (res == .initialized) {
                        self.state = .{ .wait_volume = try player.getVolume() };
                    }
                },
                .wait_volume => |wait_for| {
                    if (res != .response) continue;
                    if (res.response.handle.inner != wait_for.inner) continue;

                    const parsed = try mpris.OrgMprisMediaPlayer2Player.parseGetVolumeResponse(
                        res.response.header,
                        options,
                    );

                    std.debug.print("{d}\n", .{parsed});

                    return;
                },
            }
        }
    }

    fn close(ctx: ?*anyopaque) void {
        _ = ctx;
    }
};

pub fn main(init: std.process.Init.Minimal) !void {
    var alloc_buf: [1 * 1024 * 1024]u8 = undefined;
    var buf_alloc = sphtud.alloc.BufAllocator.init(&alloc_buf);

    const alloc = buf_alloc.allocator();

    var diagnostics = dbus.DbusErrorDiagnostics.init(try alloc.alloc(u8, 4096));

    const parse_options = dbus.ParseOptions{
        .diagnostics = &diagnostics,
    };

    var handler = try DbusHandler.init(alloc, init.environ);
    defer handler.deinit();

    handler.poll(parse_options) catch |e| {
        const diagnostics_msg = diagnostics.message();
        if (diagnostics_msg.len > 0) {
            std.log.err("{s}", .{diagnostics_msg});
        }
        var buf: [4096]u8 = undefined;

        var stderr = sphtud.io.Writer.init(2, &buf);
        try diagnostics.dumpPacket(&stderr.interface);
        try stderr.interface.flush();
        return e;
    };
}
