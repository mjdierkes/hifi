use hifi::discover::{scan_document, DocumentKind};
use url::Url;

#[test]
fn generic_html_discovers_scripts_and_preloads() {
    let result = scan_html(
        r#"
        <script src="/app.js"></script>
        <script type="module" src="/assets/index-abc123.js"></script>
        <link rel="modulepreload" href="/assets/vendor-def456.js">
    "#,
    );
    let assets = asset_urls(&result);

    assert!(assets.contains(&"https://example.com/app.js".to_string()));
    assert!(assets.contains(&"https://example.com/assets/index-abc123.js".to_string()));
    assert!(assets.contains(&"https://example.com/assets/vendor-def456.js".to_string()));
}

#[test]
fn vite_rollup_discovers_dynamic_assets() {
    let base = Url::parse("https://example.com/assets/index-abc123.js").unwrap();
    let result = scan_document(
        br#"import("./settings-def456.js"); new URL("./worker-999.js", import.meta.url);"#,
        &base,
        DocumentKind::Script,
    );
    let assets = asset_urls(&result);

    assert!(assets.contains(&"https://example.com/assets/settings-def456.js".to_string()));
    assert!(assets.contains(&"https://example.com/assets/worker-999.js".to_string()));
}

#[test]
fn webpack_and_next_runtime_literals_resolve_from_next_base() {
    let base = Url::parse("https://example.com/_next/static/chunks/app/main.js").unwrap();
    let result = scan_document(
        br#"e.u=function(e){return"static/chunks/app/dashboard-deadbeef.js"}; const data="/_next/data/b1/dashboard.json";"#,
        &base,
        DocumentKind::Script,
    );
    let assets = asset_urls(&result);

    assert!(assets.contains(
        &"https://example.com/_next/static/chunks/app/dashboard-deadbeef.js".to_string()
    ));
    assert!(result
        .findings
        .candidates
        .contains_key("/_next/data/b1/dashboard.json"));
}

#[test]
fn next_html_revision_adds_manifests() {
    let result = scan_html(
        r#"<script id="__NEXT_DATA__" type="application/json">{"buildId":"b1"}</script>"#,
    );
    let assets = asset_urls(&result);

    assert_eq!(result.revision.as_deref(), Some("b1"));
    assert!(assets.contains(&"https://example.com/_next/static/b1/_buildManifest.js".to_string()));
    assert!(assets.contains(&"https://example.com/_next/static/b1/_ssgManifest.js".to_string()));
}

#[test]
fn nuxt_and_angular_assets_are_generic_artifacts() {
    let result = scan_html(
        r#"
        <script src="/_nuxt/app.123.js"></script>
        <script src="/runtime.abc.js"></script>
        <script src="/main.def.js"></script>
        const payload="/blog/_payload.json";
    "#,
    );
    let assets = asset_urls(&result);

    assert!(assets.contains(&"https://example.com/_nuxt/app.123.js".to_string()));
    assert!(assets.contains(&"https://example.com/runtime.abc.js".to_string()));
    assert!(assets.contains(&"https://example.com/main.def.js".to_string()));
    assert!(result
        .findings
        .candidates
        .contains_key("/blog/_payload.json"));
}

fn scan_html(src: &str) -> hifi::discover::DocumentScan {
    scan_document(
        src.as_bytes(),
        &Url::parse("https://example.com/").unwrap(),
        DocumentKind::Html,
    )
}

fn asset_urls(result: &hifi::discover::DocumentScan) -> Vec<String> {
    result
        .assets
        .iter()
        .map(|asset| asset.url.as_str().to_string())
        .collect()
}
