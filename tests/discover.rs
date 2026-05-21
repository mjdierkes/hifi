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

#[test]
fn next_asset_prefix_overrides_manifest_origin() {
    let result = scan_html(
        r#"<script id="__NEXT_DATA__" type="application/json">{"buildId":"b1","assetPrefix":"https://cdn.example.com"}</script>"#,
    );
    let assets = asset_urls(&result);

    assert!(assets
        .contains(&"https://cdn.example.com/_next/static/b1/_buildManifest.js".to_string()));
    assert!(assets
        .contains(&"https://cdn.example.com/_next/static/b1/app-build-manifest.json".to_string()));
}

#[test]
fn next_base_path_prefixes_route_reconstruction() {
    let base = url::Url::parse("https://example.com/app/en/dashboard").unwrap();
    let result = scan_document(
        br#"<script id="__NEXT_DATA__" type="application/json">{"buildId":"b1","basePath":"/app","locales":["en","fr"]}</script><form><input name="$ACTION_xyz"></form>"#,
        &base,
        hifi::discover::DocumentKind::Html,
    );
    assert!(
        result.findings.apis.contains_key("/dashboard"),
        "got keys: {:?}",
        result.findings.apis.keys().collect::<Vec<_>>()
    );
}

#[test]
fn next_locale_strip_normalizes_routes() {
    let base = url::Url::parse("https://example.com/fr/about").unwrap();
    let result = scan_document(
        br#"<script id="__NEXT_DATA__" type="application/json">{"buildId":"b1","locales":["en","fr"]}</script><form><input name="$ACTION_xyz"></form>"#,
        &base,
        hifi::discover::DocumentKind::Html,
    );
    assert!(
        result.findings.apis.contains_key("/about"),
        "got keys: {:?}",
        result.findings.apis.keys().collect::<Vec<_>>()
    );
}

#[test]
fn build_manifest_routes_emit_as_findings() {
    let base = url::Url::parse("https://example.com/_next/static/b1/_buildManifest.js").unwrap();
    let result = scan_document(
        br#"self.__BUILD_MANIFEST=function(s,c){return{"/":["a.js"],"/dashboard":[s],"/about":[c],"/_app":["x"],sortedPages:["/"]}}();"#,
        &base,
        hifi::discover::DocumentKind::Manifest,
    );

    assert!(result.findings.routes.contains_key("/"));
    assert!(result.findings.routes.contains_key("/dashboard"));
    assert!(result.findings.routes.contains_key("/about"));
}

#[test]
fn app_build_manifest_routes_decode_groups() {
    let base = url::Url::parse("https://example.com/_next/static/b1/app-build-manifest.json").unwrap();
    let result = scan_document(
        br#"{"pages":{"/(marketing)/about/page":["a.js"],"/dashboard/page":["b.js"],"/blog/[slug]/page":["c.js"]}}"#,
        &base,
        hifi::discover::DocumentKind::Manifest,
    );

    assert!(result.findings.routes.contains_key("/about"));
    assert!(result.findings.routes.contains_key("/dashboard"));
    assert!(result.findings.routes.contains_key("/blog/[slug]"));
}

#[test]
fn comment_and_identifier_substrings_are_not_assets() {
    // Without quoted-string context, these regions look like asset
    // literals after walk_token_start. They should now be rejected.
    let result = scan_html(
        r#"
        <script>
        // /_next/data/b1/notes.json -- comment, not a real URL
        var path = _next_data_lookup(/_next/data/b1/inline);
        const valid = "/_next/data/b1/dashboard.json";
        </script>
    "#,
    );
    assert!(result
        .findings
        .candidates
        .contains_key("/_next/data/b1/dashboard.json"));
    assert!(!result.findings.candidates.contains_key("/_next/data/b1/notes.json"));
    assert!(!result.findings.candidates.contains_key("/_next/data/b1/inline"));
}

#[test]
fn next_15_instrumentation_chunks_are_skipped() {
    let base = url::Url::parse("https://example.com/").unwrap();
    let result = scan_document(
        br#"<script src="/_next/static/chunks/instrumentation-abc.js"></script>"#,
        &base,
        hifi::discover::DocumentKind::Html,
    );
    let assets = asset_urls(&result);
    assert!(
        !assets
            .iter()
            .any(|url| url.contains("instrumentation-abc.js")),
        "Next 15 instrumentation chunk leaked through: {assets:?}",
    );
}

#[test]
fn provenance_tags_distinguish_finding_sources() {
    use hifi::scan::FindingSource;
    let base = url::Url::parse("https://example.com/_next/static/b1/app-build-manifest.json")
        .unwrap();
    let result = scan_document(
        br#"{"pages":{"/dashboard/page":["a.js"]}}"#,
        &base,
        hifi::discover::DocumentKind::Manifest,
    );
    assert_eq!(
        result.findings.provenance.get("/dashboard"),
        Some(&FindingSource::ManifestParsed),
    );
    assert!(FindingSource::ManifestParsed.is_high_confidence());
    assert!(!FindingSource::Literal.is_high_confidence());
}

#[test]
fn provenance_promotes_to_highest_seen_source() {
    use hifi::scan::FindingSource;
    // The same route appears both as a literal-grep candidate and as a typed
    // flight href. Provenance should reflect the higher-confidence source.
    let result = scan_html(
        r#"<script>const r="/dashboard";</script><script>self.__next_f.push([1,"0:{\"href\":\"/dashboard\"}"])</script>"#,
    );
    assert_eq!(
        result.findings.provenance.get("/dashboard"),
        Some(&FindingSource::FlightTyped),
    );
}

#[test]
fn server_action_is_marked_high_confidence() {
    use hifi::scan::FindingSource;
    let base = url::Url::parse("https://example.com/checkout").unwrap();
    let result = scan_document(
        br#"<form><input name="$ACTION_xyz"></form>"#,
        &base,
        hifi::discover::DocumentKind::Html,
    );
    assert_eq!(
        result.findings.provenance.get("/checkout"),
        Some(&FindingSource::ServerAction),
    );
}

#[test]
fn api_call_sites_record_api_call_provenance() {
    use hifi::scan::FindingSource;
    let result = scan_html(r#"<script>fetch("/api/widgets",{method:"POST"})</script>"#);
    assert_eq!(
        result.findings.provenance.get("/api/widgets"),
        Some(&FindingSource::ApiCall),
    );
}

#[test]
fn flight_typed_walk_extracts_href_routes() {
    let result = scan_html(
        r#"<script>self.__next_f.push([1,"0:[\"$\",\"a\",null,{\"href\":\"/profile\",\"action\":\"/api/save\"}]\n"])</script>"#,
    );
    assert!(result.findings.routes.contains_key("/profile"));
    assert!(
        result.findings.routes.contains_key("/api/save")
            || result.findings.apis.contains_key("/api/save")
            || result.findings.candidates.contains_key("/api/save"),
        "got routes={:?} apis={:?} candidates={:?}",
        result.findings.routes.keys().collect::<Vec<_>>(),
        result.findings.apis.keys().collect::<Vec<_>>(),
        result.findings.candidates.keys().collect::<Vec<_>>(),
    );
}

#[test]
fn flight_large_payload_is_not_truncated_at_64k() {
    // Construct a flight push whose embedded payload exceeds the old 64KB cap.
    let mut middle = String::with_capacity(80_000);
    for i in 0..1500 {
        middle.push_str(&format!("\\\"pad_{i}\\\":\\\"x\\\","));
    }
    let html = format!(
        r#"<script>self.__next_f.push([1,"0:{{{middle}\"href\":\"/late-route\"}}\n"])</script>"#
    );
    let result = scan_html(&html);
    assert!(
        result.findings.routes.contains_key("/late-route"),
        "large flight payload was truncated; routes={:?}",
        result.findings.routes.keys().collect::<Vec<_>>(),
    );
}

#[test]
fn scan_document_with_config_uses_parent_locale() {
    use hifi::discover::scan_document_with_config;
    use hifi::scan::next::NextConfig;
    let cfg = NextConfig {
        build_id: Some("b1".into()),
        locales: vec!["en".into(), "fr".into()],
        ..Default::default()
    };
    let base = url::Url::parse("https://example.com/fr/about.rsc").unwrap();
    let result = scan_document_with_config(
        br#"<form><input name="$ACTION_xyz"></form>"#,
        &base,
        hifi::discover::DocumentKind::Payload,
        Some(&cfg),
    );
    assert!(
        result.findings.apis.contains_key("/about"),
        "got: {:?}",
        result.findings.apis.keys().collect::<Vec<_>>()
    );
}

#[test]
fn app_router_route_groups_decoded_in_payload_route() {
    let base = url::Url::parse("https://example.com/(marketing)/about.rsc").unwrap();
    let result = scan_document(
        br#"<script>const a="$ACTION_xyz";</script>"#,
        &base,
        hifi::discover::DocumentKind::Payload,
    );
    assert!(
        result.findings.apis.contains_key("/about"),
        "got keys: {:?}",
        result.findings.apis.keys().collect::<Vec<_>>()
    );
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
