const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const sphtud_dep = b.dependency("sphtud", .{});
    const sphtud = sphtud_dep.module("sphtud");

    const dbus_mod = b.addModule("sphdbus", .{
        .root_source_file = b.path("src/sphdbus.zig"),
        .target = target,
        .optimize = optimize,
    });

    const generate = b.addExecutable(.{
        .name = "generate",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/generate.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    generate.root_module.addImport("sphtud", sphtud);

    const run_generate_mpris = b.addRunArtifact(generate);
    run_generate_mpris.addFileArg(b.path("res/org.mpris.MediaPlayer2.Player.xml"));
    const mpris_file = run_generate_mpris.addOutputFileArg("mpris.zig");

    const mpris_mod = b.createModule(.{
        .root_source_file = mpris_file,
    });
    mpris_mod.addImport("sphdbus", dbus_mod);

    const example = b.addExecutable(.{
        .name = "mpris_example",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/example.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    example.root_module.addImport("sphtud", sphtud);
    example.root_module.addImport("sphdbus", dbus_mod);
    example.root_module.addImport("mpris", mpris_mod);

    const service_example = b.addExecutable(.{
        .name = "service_example",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/service_example.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    service_example.root_module.addImport("sphtud", sphtud);
    service_example.root_module.addImport("sphdbus", dbus_mod);

    const dbus_tests = b.addTest(.{
        .name = "dbus_tests",
        .root_module = dbus_mod,
    });
    dbus_tests.use_llvm = true;
    dbus_tests.root_module.addImport("sphtud", sphtud);
    dbus_tests.root_module.addImport("mpris", mpris_mod);

    b.installArtifact(example);
    b.installArtifact(generate);
    b.installArtifact(service_example);
    b.installArtifact(dbus_tests);
}
