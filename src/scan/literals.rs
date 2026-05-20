#[rustfmt::skip]
pub const CALL_LITERALS: &[&str] = &[
    "fetch(", "fetch (", ".fetch(", "axios(", "axios.get(", "axios.post(", "axios.put(",
    "axios.delete(", "axios.patch(", "axios.request(", "$fetch(", "ofetch(", "ky.get(",
    "ky.post(", "ky(", "got(", "request(", "url:\"", "url:'", "url: \"", "url: '",
    "endpoint:\"", "endpoint:'", ".get(", ".post(", ".put(", ".delete(", ".patch(",
    "useSWR(", "useSWRMutation(", "useSWRInfinite(", "new Request(",
];

#[rustfmt::skip]
pub const ROUTE_CALL_LITERALS: &[&str] = &[
    "router.push(", "router.replace(", "router.prefetch(", ".push(", ".replace(",
    ".prefetch(", "navigate(",
];
pub const ROUTE_VALUE_LITERALS: &[&str] = &["href", "pathname", "asPath", "action", "formAction"];
pub const ROUTE_START_LITERALS: &[&str] = &["\"/", "'/", "`/", "\\\"/", "\\'/"];

#[rustfmt::skip]
pub const ROUTE_BAD_EXTS: &[&str] = &[
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf",
    ".ico", ".webp", ".mp4", ".webm", ".map", ".json", ".txt", ".xml",
];
#[rustfmt::skip]
pub const BAD_EXTS: &[&str] = &[
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf",
    ".ico", ".webp", ".mp4", ".webm", ".map",
];
#[rustfmt::skip]
pub const SKIPPED_CHUNK_FRAGMENTS: &[&str] = &[
    "framework-", "polyfills-", "webpack-", "main-", "main-app-", "_next/static/chunks/_turbopack_",
    "[turbopack]_runtime", "[next]_internal_", "react-refresh", "next/dist/",
];
