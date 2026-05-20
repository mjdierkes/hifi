use hifi::html::extract_chunks;
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
