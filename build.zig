const std = @import("std");

pub fn genService(b: *std.Build, me: *std.Build.Dependency, path: std.Build.LazyPath) *std.Build.Module {
    const gen_service = me.artifact("generate_service");
    const sphdbus_mod = me.module("sphdbus");

    return runGenService(b, gen_service, sphdbus_mod, path);
}

fn runGenService(b: *std.Build, exe: *std.Build.Step.Compile, sphdbus: *std.Build.Module, path: std.Build.LazyPath) *std.Build.Module {
    const run_gen_service = b.addRunArtifact(exe);
    run_gen_service.addFileArg(path);
    const test_service_path = run_gen_service.addOutputFileArg("service.zig");
    _ = run_gen_service.addDepFileOutputArg("deps");

    const service_mod = b.createModule(.{
        .root_source_file = test_service_path,
    });
    service_mod.addImport("sphdbus", sphdbus);
    return service_mod;
}

pub const ClientGenerator = struct {
    b: *std.Build,
    exe: *std.Build.Step.Compile,
    dbus: *std.Build.Module,

    pub fn init(b: *std.Build, sphtud: *std.Build.Module, dbus: *std.Build.Module) ClientGenerator {
        const exe = b.addExecutable(.{
            .name = "generate",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/generate.zig"),
                .target = b.graph.host,
                .optimize = .Debug,
            }),
        });
        exe.root_module.addImport("sphtud", sphtud);

        return .{
            .b = b,
            .exe = exe,
            .dbus = dbus,
        };
    }

    pub fn genClientMod(self: ClientGenerator, xml_path: std.Build.LazyPath) *std.Build.Module {
        const run = self.b.addRunArtifact(self.exe);
        run.addFileArg(xml_path);
        const out_path = run.addOutputFileArg("mod.zig");
        const mod = self.b.createModule(.{
            .root_source_file = out_path,
        });
        mod.addImport("sphdbus", self.dbus);

        return mod;
    }
};

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

    const cg = ClientGenerator.init(b, sphtud, dbus_mod);

    const mpris_mod = cg.genClientMod(b.path("res/org.mpris.MediaPlayer2.Player.xml"));

    const generate_service = b.addExecutable(.{
        .name = "generate_service",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/generate_service.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    generate_service.root_module.addImport("sphtud", sphtud);

    const mpris_service_mod = runGenService(b, generate_service, dbus_mod, b.path("res/mpris_serivce.xml"));
    mpris_service_mod.addImport("sphdbus", dbus_mod);

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
    service_example.root_module.addImport("test_service", runGenService(b, generate_service, dbus_mod, b.path("res/test_service.xml")));

    const dbus_tests = b.addTest(.{
        .name = "dbus_tests",
        .root_module = dbus_mod,
    });
    dbus_tests.root_module.addImport("sphtud", sphtud);
    dbus_tests.root_module.addImport("mpris", mpris_mod);
    dbus_tests.root_module.addImport("mpris_service", mpris_service_mod);

    b.installArtifact(example);
    b.installArtifact(cg.exe);
    b.installArtifact(generate_service);
    b.installArtifact(service_example);
    b.installArtifact(dbus_tests);
}
