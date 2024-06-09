const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "packet-sniff",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe.addIncludePath(.{ .path = "/usr/include/arpa" });
    exe.linkSystemLibrary("pcap");
    exe.linkSystemLibrary("c");
    // exe.linkSystemLibrary("arpa");

    b.installArtifact(exe);

    const run_exe = b.addRunArtifact(exe);

    const run_step = b.step("run", "Run the application");
    run_step.dependOn(&run_exe.step);
}
