// Tunable scanning rules. Edit here without touching scan logic.

/// Call-site anchors: places where a URL string literal is the next token.
pub const CALL_LITERALS: &[&str] = &[
    "fetch(",
    "fetch (",
    ".fetch(",
    "axios(",
    "axios.get(",
    "axios.post(",
    "axios.put(",
    "axios.delete(",
    "axios.patch(",
    "axios.request(",
    "$fetch(",
    "ofetch(",
    "ky.get(",
    "ky.post(",
    "ky(",
    "got(",
    "request(",
    "url:\"",
    "url:'",
    "url: \"",
    "url: '",
    "endpoint:\"",
    "endpoint:'",
];

/// Shape markers searched inside the window around each call.
pub const SHAPE_LITERALS: &[&str] = &[
    "method:\"POST\"",
    "method:'POST'",
    "method:\"PUT\"",
    "method:'PUT'",
    "method:\"DELETE\"",
    "method:'DELETE'",
    "method:\"PATCH\"",
    "method:'PATCH'",
    "method:\"GET\"",
    "method:'GET'",
    "body:",
    "headers:",
    "Content-Type",
    "application/json",
    "Authorization",
    "Bearer",
];

/// Asset extensions to exclude from candidate URLs.
pub const BAD_EXTS: &[&str] = &[
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".ico",
    ".webp", ".mp4", ".webm", ".map",
];

/// Substrings in Next.js chunk filenames we skip (framework / vendor / runtime).
pub const SKIPPED_CHUNK_FRAGMENTS: &[&str] = &["framework-", "polyfills-", "webpack-", "main-"];

pub fn method_from_pattern(p: &str) -> &'static str {
    match p {
        "method:\"POST\"" | "method:'POST'" => "POST",
        "method:\"PUT\"" | "method:'PUT'" => "PUT",
        "method:\"DELETE\"" | "method:'DELETE'" => "DELETE",
        "method:\"PATCH\"" | "method:'PATCH'" => "PATCH",
        "method:\"GET\"" | "method:'GET'" => "GET",
        _ => "GET",
    }
}
