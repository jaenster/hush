//! Validation for secret key names.
//!
//! A key is injected into a child's environment (`hush run`) and emitted as a
//! shell `export` (`hush env`), so it must be a valid POSIX environment-variable
//! name: a non-empty `[A-Za-z_][A-Za-z0-9_]*`. Anything else risks a malformed
//! `execve` env block (crash) or shell injection in `hush env`.

const std = @import("std");

pub fn isEnvVarName(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s, 0..) |c, i| {
        const ok = switch (c) {
            'A'...'Z', 'a'...'z', '_' => true,
            '0'...'9' => i != 0,
            else => false,
        };
        if (!ok) return false;
    }
    return true;
}

/// Env var names that change how a *child process* loads code or resolves
/// commands — setting any of these is effectively arbitrary code execution in
/// the spawned process. A bulk source (an included note/vault) must never
/// silently inject one; it has to be explicitly declared in the committed
/// manifest, where a reviewer can see it. This is the floor that applies even
/// with no manifest present.
pub fn isDangerous(name: []const u8) bool {
    // The dynamic-linker families take arbitrary suffixes (LD_PRELOAD,
    // DYLD_INSERT_LIBRARIES, LD_AUDIT, ...), so match the whole prefix.
    if (std.mem.startsWith(u8, name, "LD_")) return true;
    if (std.mem.startsWith(u8, name, "DYLD_")) return true;
    const exact = [_][]const u8{
        "PATH", // command resolution
        "IFS", // shell word-splitting
        "ENV", "BASH_ENV", "ZDOTDIR", // shell startup files
        "NODE_OPTIONS", // node: --require a module
        "PYTHONPATH", "PYTHONSTARTUP", // python import path / REPL init
        "PERL5LIB", "PERL5OPT", // perl
        "RUBYLIB", "RUBYOPT", // ruby
        "GIT_SSH", "GIT_SSH_COMMAND", "GIT_EXTERNAL_DIFF", "GIT_PAGER", // git hooks
        "PAGER", "EDITOR", "VISUAL", // programs other tools shell out to
    };
    for (exact) |e| if (std.mem.eql(u8, name, e)) return true;
    return false;
}

test "valid names" {
    try std.testing.expect(isEnvVarName("API_KEY"));
    try std.testing.expect(isEnvVarName("_x"));
    try std.testing.expect(isEnvVarName("a1_B2"));
    try std.testing.expect(isEnvVarName("lowercase_ok"));
}

test "invalid names" {
    try std.testing.expect(!isEnvVarName(""));
    try std.testing.expect(!isEnvVarName("1ABC")); // leading digit
    try std.testing.expect(!isEnvVarName("A=B")); // '='
    try std.testing.expect(!isEnvVarName("INJ;echo x")); // shell metachars
    try std.testing.expect(!isEnvVarName("HAS SPACE"));
    try std.testing.expect(!isEnvVarName("dot.ted"));
}

test "dangerous names" {
    try std.testing.expect(isDangerous("PATH"));
    try std.testing.expect(isDangerous("LD_PRELOAD"));
    try std.testing.expect(isDangerous("LD_LIBRARY_PATH"));
    try std.testing.expect(isDangerous("DYLD_INSERT_LIBRARIES"));
    try std.testing.expect(isDangerous("NODE_OPTIONS"));
    try std.testing.expect(isDangerous("BASH_ENV"));
    try std.testing.expect(isDangerous("GIT_SSH_COMMAND"));
    // Ordinary app vars are fine to inject from a bulk source.
    try std.testing.expect(!isDangerous("DATABASE_URL"));
    try std.testing.expect(!isDangerous("API_KEY"));
    try std.testing.expect(!isDangerous("PORT"));
    try std.testing.expect(!isDangerous("NODE_ENV"));
}
