const std = @import("std");
const sphtud = @import("sphtud");
const builtin = @import("builtin");
const dbus = @import("sphdbus");
const mpris = @import("mpris");

const DbusHandler = struct {
    connection: dbus.DbusConnection,
    state: union(enum) {
        wait_initialize,
        wait_volume: dbus.CallHandle,
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

            const player = mpris.OrgMprisMediaPlayer2Player{
                .connection = &self.connection,
                .service = "org.mpris.MediaPlayer2.spotify",
                .object_path = "/org/mpris/MediaPlayer2",
            };

            switch (self.state) {
                .wait_initialize => {
                    if (res == .initialized) {
                        self.state = .{ .wait_volume = try player.getMetadata() };
                    }
                },
                .wait_volume => |wait_for| {
                    if (res != .response) continue;
                    if (res.response.handle.inner != wait_for.inner) continue;

                    const f = try std.fs.cwd().createFile("dump.bin", .{});
                    defer f.close();

                    try f.writeAll(res.response.header.body);

                    const parsed = try mpris.OrgMprisMediaPlayer2Player.parseGetMetadataResponse(
                        res.response.header,
                    );

                    var it = parsed.iter();
                    while (try it.next()) |kv| {

                        // FIXME: Probably should be part of lib?
                        const KnownSigantures = enum {
                            s,
                            t,
                            d,
                            i,
                        };
                        std.debug.print("{s}: ", .{kv.key.inner});
                        const parsed_sig = std.meta.stringToEnum(KnownSigantures, kv.val.signature()) orelse {
                            std.debug.print("(cannot print {s})\n", .{kv.val.signature()});
                            continue;
                        };

                        switch (parsed_sig) {
                            .s => std.debug.print("{s}\n", .{(try kv.val.toConcrete(dbus.DbusString, res.response.header.endianness)).inner}),
                            .t => std.debug.print("{d}\n", .{(try kv.val.toConcrete(u64, res.response.header.endianness))}),
                            .d => std.debug.print("{d}\n", .{(try kv.val.toConcrete(f64, res.response.header.endianness))}),
                            .i => std.debug.print("{d}\n", .{(try kv.val.toConcrete(i32, res.response.header.endianness))}),
                        }
                    }

                    return;
                },
            }
        }
    }

    fn close(ctx: ?*anyopaque) void {
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
