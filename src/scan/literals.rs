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
    ".get(",
    ".post(",
    ".put(",
    ".delete(",
    ".patch(",
    "useSWR(",
    "useSWRMutation(",
    "useSWRInfinite(",
    "new Request(",
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

pub const SKIPPED_CHUNK_FRAGMENTS: &[&str] = &[
    // webpack runtime / shared chunks
    "framework-",
    "polyfills-",
    "webpack-",
    "main-",
    "main-app-",
    // turbopack runtime chunks (Next 15+)
    "_next/static/chunks/_turbopack_",
    "[turbopack]_runtime",
    "[next]_internal_",
    // react / next shared vendor chunks
    "react-refresh",
    "next/dist/",
];
