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

pub const BAD_EXTS: &[&str] = &[
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".ico",
    ".webp", ".mp4", ".webm", ".map",
];

pub const SKIPPED_CHUNK_FRAGMENTS: &[&str] = &["framework-", "polyfills-", "webpack-", "main-"];
