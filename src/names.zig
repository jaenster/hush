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
