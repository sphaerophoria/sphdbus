const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const sphtud_dep = b.dependency("sphtud", .{});
    const sphtud = sphtud_dep.module("sphtud");

    const dbus_mod = b.addModule("sphdbus", .{
        .root_source_file = b.path("src/sphdbus.zig"),
    });
    dbus_mod.addImport("sphtud", sphtud);

    const example = b.addExecutable(.{
        .name = "sphdbus",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    example.root_module.addImport("sphtud", sphtud);
    example.root_module.addImport("sphdbus", dbus_mod);

    const generate = b.addExecutable(.{
        .name = "generate",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/generate.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    generate.root_module.addImport("sphtud", sphtud);

    const run_generate_login1 = b.addRunArtifact(generate);
    run_generate_login1.addFileArg(b.path("org.freedesktop.login1.Manager.xml"));
    const login1_file = run_generate_login1.addOutputFileArg("manager.zig");

    const manager_mod = b.createModule(.{
        .root_source_file = login1_file,
    });
    manager_mod.addImport("sphdbus", dbus_mod);
    manager_mod.addImport("sphtud", sphtud);

    const run_generate_mpris = b.addRunArtifact(generate);
    run_generate_mpris.addFileArg(b.path("org.mpris.MediaPlayer2.Player.xml"));
    const mpris_file = run_generate_mpris.addOutputFileArg("mpris.zig");

    const mpris_mod = b.createModule(.{
        .root_source_file = mpris_file,
    });
    mpris_mod.addImport("sphdbus", dbus_mod);
    mpris_mod.addImport("sphtud", sphtud);

    example.root_module.addImport("login1", manager_mod);
    example.root_module.addImport("mpris", mpris_mod);

    b.installArtifact(example);
    b.installArtifact(generate);
}
