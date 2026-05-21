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
fn non_next_build_id_does_not_create_revision_or_manifests() {
    let result = scan_html(
        r#"
        <script>window.__APP_DATA__={"buildId":"viteish"};</script>
        <script type="module" src="/assets/app.js"></script>
    "#,
    );
    let assets = asset_urls(&result);

    assert_eq!(result.revision, None);
    assert!(assets.contains(&"https://example.com/assets/app.js".to_string()));
    assert!(!assets
        .iter()
        .any(|asset| asset.contains("/_next/static/viteish/")));
}

#[test]
fn next_payloads_and_rsc_prefetches_are_fetchable_assets() {
    let result = scan_html(
        r#"
        <script>
        const data="/_next/data/b1/dashboard.json";
        const rsc="/dashboard?_rsc=abc";
        const segment="/dashboard.segments/dashboard.segment.rsc";
        </script>
    "#,
    );
    let assets = asset_urls(&result);

    assert!(assets.contains(&"https://example.com/_next/data/b1/dashboard.json".to_string()));
    assert!(assets.contains(&"https://example.com/dashboard?_rsc=abc".to_string()));
    assert!(assets
        .contains(&"https://example.com/dashboard.segments/dashboard.segment.rsc".to_string()));
}

#[test]
fn minified_rsc_property_accesses_are_not_treated_as_assets() {
    // Real-world false positives from Next.js minified RSC code: property
    // accesses like `x.rsc`, `rsc:E.rsc`, and concatenated chunk paths like
    // `"_next/static/chunks/" + n + ".rsc"` produce `.rsc` substrings that
    // are not real URLs.
    let result = scan_html(
        r#"
        <script>
        var t={children:x.rsc,rsc:E.rsc};
        var u="/_next/static/chunks/"+n+".rsc";
        var v="/_next/static/chunks/.segment.rsc";
        var w="/_next/static/chunks/"+s+".head.rsc";
        </script>
    "#,
    );
    for noise in [
        "x.rsc",
        "E.rsc",
        ".segment.rsc",
        "/_next/static/chunks/.rsc",
        "/_next/static/chunks/.segment.rsc",
        "/_next/static/chunks/s.head.rsc",
    ] {
        assert!(
            !asset_urls(&result).iter().any(|u| u.ends_with(noise)),
            "garbage `.rsc` token became a fetchable asset: {noise}"
        );
    }
}

#[test]
fn next_manifests_follow_observed_static_mount() {
    let result = scan_document(
        br#"
        <script id="__NEXT_DATA__" type="application/json">{"buildId":"b1"}</script>
        <script src="https://cdn.example.com/docs/_next/static/chunks/app.js"></script>
    "#,
        &Url::parse("https://example.com/docs/").unwrap(),
        DocumentKind::Html,
    );
    let assets = asset_urls(&result);

    assert!(assets
        .contains(&"https://cdn.example.com/docs/_next/static/b1/_buildManifest.js".to_string()));
    assert!(assets
        .contains(&"https://cdn.example.com/docs/_next/static/b1/_ssgManifest.js".to_string()));
}

#[test]
fn next_flight_and_action_markers_add_browser_surface() {
    let result = scan_document(
        br#"
        <script>self.__next_f.push([1,"fetch(\"/api/flight\",{method:\"POST\"})"])</script>
        <form><input type="hidden" name="$ACTION_ID_abc"></form>
    "#,
        &Url::parse("https://example.com/checkout").unwrap(),
        DocumentKind::Html,
    );

    assert_eq!(result.findings.apis["/api/flight"].methods_csv(), "POST");
    assert_eq!(result.findings.apis["/checkout"].methods_csv(), "POST");
    assert_eq!(
        result.findings.apis["/checkout"].flags_csv(),
        "body,next-action"
    );
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
