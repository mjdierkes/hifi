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

pub const ROUTE_CALL_LITERALS: &[&str] = &[
    "router.push(",
    "router.replace(",
    "router.prefetch(",
    ".push(",
    ".replace(",
    ".prefetch(",
    "navigate(",
];
pub const ROUTE_VALUE_LITERALS: &[&str] = &["href", "pathname", "asPath", "action", "formAction"];
pub const ROUTE_START_LITERALS: &[&str] = &["\"/", "'/", "`/", "\\\"/", "\\'/"];

#[rustfmt::skip]
pub const ROUTE_BAD_EXTS: &[&str] = &[
    ".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf",
    ".ico", ".webp", ".mp4", ".webm", ".map", ".json", ".txt", ".xml", ".wasm",
];
#[rustfmt::skip]
pub const BAD_EXTS: &[&str] = &[
    ".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf",
    ".ico", ".webp", ".mp4", ".webm", ".map", ".wasm",
];
