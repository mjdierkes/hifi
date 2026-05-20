// Call-site anchors. `METHOD_HINTS` parallels this array — None means infer
// the method from shape literals, Some(_) means the anchor itself implies it.
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
];

pub const METHOD_HINTS: &[Option<&str>] = &[
    None,         // fetch(
    None,         // fetch (
    None,         // .fetch(
    None,         // axios(
    Some("GET"),  // axios.get(
    Some("POST"), // axios.post(
    Some("PUT"),  // axios.put(
    Some("DELETE"), // axios.delete(
    Some("PATCH"), // axios.patch(
    None,         // axios.request(
    None,         // $fetch(
    None,         // ofetch(
    Some("GET"),  // ky.get(
    Some("POST"), // ky.post(
    None,         // ky(
    None,         // got(
    None,         // request(
    None,         // url:"
    None,         // url:'
    None,         // url: "
    None,         // url: '
    None,         // endpoint:"
    None,         // endpoint:'
    Some("GET"),  // .get(
    Some("POST"), // .post(
    Some("PUT"),  // .put(
    Some("DELETE"), // .delete(
    Some("PATCH"), // .patch(
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
