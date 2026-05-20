use hifi::html::{extract_chunk_refs, extract_chunks};
use url::Url;

#[test]
fn extracts_next_script_chunks_without_framework_noise() {
    let base = Url::parse("https://example.com/app/page").unwrap();
    let html = r#"
        <script src="/_next/static/chunks/framework-abc.js"></script>
        <script defer SRC='/_next/static/chunks/app/dashboard-123.js'></script>
        <script src="/assets/site.js"></script>
    "#;

    let chunks = extract_chunks(html.as_bytes(), &base);

    assert_eq!(chunks.len(), 1);
    assert_eq!(
        chunks[0].as_str(),
        "https://example.com/_next/static/chunks/app/dashboard-123.js"
    );
}

#[test]
fn reads_quoted_and_unquoted_chunk_urls() {
    let base = Url::parse("https://example.com").unwrap();
    let html = r#"<script src="/_next/a.js"></script><script src=/_next/b.js async>"#;
    let chunks = extract_chunks(html.as_bytes(), &base);
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0].as_str(), "https://example.com/_next/a.js");
    assert_eq!(chunks[1].as_str(), "https://example.com/_next/b.js");
}

#[test]
fn extracts_absolute_cdn_chunk_urls() {
    let base = Url::parse("https://example.com").unwrap();
    let html =
        r#"<script src="https://cdn.example.com/_next/static/chunks/app/page-abc.js"></script>"#;
    let chunks = extract_chunks(html.as_bytes(), &base);
    assert_eq!(chunks.len(), 1);
    assert_eq!(
        chunks[0].as_str(),
        "https://cdn.example.com/_next/static/chunks/app/page-abc.js"
    );
}

#[test]
fn skips_turbopack_runtime_chunks() {
    let base = Url::parse("https://example.com").unwrap();
    let html = r#"
        <script src="/_next/static/chunks/_turbopack_runtime.js"></script>
        <script src="/_next/static/chunks/app/page-xyz.js"></script>
    "#;
    let chunks = extract_chunks(html.as_bytes(), &base);
    assert_eq!(chunks.len(), 1);
    assert!(chunks[0].as_str().ends_with("page-xyz.js"));
}

#[test]
fn discovers_nested_chunk_refs_in_chunk_body() {
    let base = Url::parse("https://example.com/_next/static/chunks/main-app.js").unwrap();
    let body = br#"
        e.u=function(e){return"static/chunks/app/dashboard-deadbeef.js"};
        var a="/_next/static/chunks/app/settings-cafebabe.js";
        var b="https://cdn.example.com/_next/static/chunks/app/users-f00d.js";
    "#;
    let refs = extract_chunk_refs(body, &base);
    let urls: Vec<_> = refs.iter().map(|u| u.as_str()).collect();
    assert!(urls
        .iter()
        .any(|u| u.ends_with("app/dashboard-deadbeef.js")));
    assert!(urls.iter().any(|u| u.ends_with("app/settings-cafebabe.js")));
    assert!(urls
        .iter()
        .any(|u| *u == "https://cdn.example.com/_next/static/chunks/app/users-f00d.js"));
}

#[test]
fn deduplicates_repeated_chunk_urls() {
    let base = Url::parse("https://example.com").unwrap();
    let html = r#"
        <script src="/_next/a.js"></script>
        <link rel="preload" href="/_next/a.js">
        <script src="/_next/b.js"></script>
    "#;

    let chunks = extract_chunks(html.as_bytes(), &base);

    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0].as_str(), "https://example.com/_next/a.js");
    assert_eq!(chunks[1].as_str(), "https://example.com/_next/b.js");
}
