const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Homebrew (Apple Silicon) prefix for libsodium headers/libs.
    const brew_include = "/opt/homebrew/include";
    const brew_lib = "/opt/homebrew/lib";

    // Shared core: protocol, crypto, store. Links libsodium via C.
    const core = b.addModule("hush", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    core.addIncludePath(.{ .cwd_relative = brew_include });
    core.addLibraryPath(.{ .cwd_relative = brew_lib });
    core.linkSystemLibrary("sodium", .{ .preferred_link_mode = .static });

    // Daemon: hushd
    const daemon = b.addExecutable(.{
        .name = "hushd",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/daemon/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{.{ .name = "hush", .module = core }},
        }),
    });
    daemon.root_module.addIncludePath(.{ .cwd_relative = brew_include });
    daemon.root_module.addLibraryPath(.{ .cwd_relative = brew_lib });
    daemon.root_module.linkSystemLibrary("sodium", .{ .preferred_link_mode = .static });
    // Keychain storage for the vault data key.
    daemon.root_module.linkFramework("CoreFoundation", .{});
    daemon.root_module.linkFramework("Security", .{});
    b.installArtifact(daemon);

    // CLI: hush
    const cli = b.addExecutable(.{
        .name = "hush",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/cli/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{.{ .name = "hush", .module = core }},
        }),
    });
    cli.root_module.addIncludePath(.{ .cwd_relative = brew_include });
    cli.root_module.addLibraryPath(.{ .cwd_relative = brew_lib });
    cli.root_module.linkSystemLibrary("sodium", .{ .preferred_link_mode = .static });
    b.installArtifact(cli);

    // `zig build run-daemon`
    const run_daemon = b.addRunArtifact(daemon);
    run_daemon.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_daemon.addArgs(args);
    b.step("run-daemon", "Run hushd").dependOn(&run_daemon.step);

    // `zig build run -- <cli args>`
    const run_cli = b.addRunArtifact(cli);
    run_cli.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cli.addArgs(args);
    b.step("run", "Run hush CLI").dependOn(&run_cli.step);

    // Tests over the core module.
    const core_tests = b.addTest(.{ .root_module = core });
    const run_core_tests = b.addRunArtifact(core_tests);

    // Tests over the daemon-only modules (providers, etc.).
    const providers_mod = b.createModule(.{
        .root_source_file = b.path("src/daemon/providers.zig"),
        .target = target,
        .optimize = optimize,
    });
    const providers_tests = b.addTest(.{ .root_module = providers_mod });
    const run_providers_tests = b.addRunArtifact(providers_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_core_tests.step);
    test_step.dependOn(&run_providers_tests.step);
}
