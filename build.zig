const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Create the runquic module
    const runquic_module = b.createModule(.{
        .root_source_file = b.path("lib/runquic.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Export the module so it can be used by other projects
    _ = b.addModule("runquic", .{
        .root_source_file = b.path("lib/runquic.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Build the library
    const lib = b.addLibrary(.{
        .name = "runquic",
        .root_module = runquic_module,
        .linkage = .static,
    });

    b.installArtifact(lib);

    // Unit tests
    const lib_unit_tests = b.addTest(.{
        .root_module = runquic_module,
    });

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
}
