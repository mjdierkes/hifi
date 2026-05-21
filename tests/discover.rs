use hifi::discover::{scan_document, scan_document_with_config, DocumentKind};
use hifi::scan::{next::NextConfig, EvidenceKind, Extractor};
use url::Url;

#[test]
fn discovers_static_dynamic_and_framework_assets() {
    let result = scan_html(
        r#"
        <script src="/app.js"></script>
        <SCRIPT SRC="/upper.js"></SCRIPT>
        <script type="module" src="/assets/index-abc123.js"></script>
        <link rel="modulepreload" href="/assets/vendor-def456.js">
        <script src="/_nuxt/app.123.js"></script>
        <script src="/runtime.abc.js"></script>
        <script src="/main.def.js"></script>
        const payload="/blog/_payload.json";
    "#,
    );
    assert_assets(
        &result,
        &[
            "https://example.com/app.js",
            "https://example.com/upper.js",
            "https://example.com/assets/index-abc123.js",
            "https://example.com/assets/vendor-def456.js",
            "https://example.com/_nuxt/app.123.js",
            "https://example.com/runtime.abc.js",
            "https://example.com/main.def.js",
        ],
    );
    assert_candidate(&result, "/blog/_payload.json");

    let base = url("https://example.com/assets/index-abc123.js");
    let result = scan(
        br#"import("./settings-def456.js"); new URL("./worker-999.js", import.meta.url);"#,
        &base,
        DocumentKind::Script,
    );
    assert_assets(
        &result,
        &[
            "https://example.com/assets/settings-def456.js",
            "https://example.com/assets/worker-999.js",
        ],
    );
}

#[test]
fn next_assets_manifests_and_payloads_resolve_from_context() {
    let result = scan(
        br#"e.u=function(e){return"static/chunks/app/dashboard-deadbeef.js"}; const data="/_next/data/b1/dashboard.json";"#,
        &url("https://example.com/_next/static/chunks/app/main.js"),
        DocumentKind::Script,
    );
    assert_assets(
        &result,
        &["https://example.com/_next/static/chunks/app/dashboard-deadbeef.js"],
    );
    assert_candidate(&result, "/_next/data/b1/dashboard.json");

    let result = scan_html(
        r#"
        <script id="__NEXT_DATA__" type="application/json">{"buildId":"b1"}</script>
        <script>
        const data="/_next/data/b1/dashboard.json";
        const rsc="/dashboard?_rsc=abc";
        const segment="/dashboard.segments/dashboard.segment.rsc";
        </script>
    "#,
    );
    assert_eq!(result.revision.as_deref(), Some("b1"));
    assert_assets(
        &result,
        &[
            "https://example.com/_next/static/b1/_buildManifest.js",
            "https://example.com/_next/static/b1/_ssgManifest.js",
            "https://example.com/_next/data/b1/dashboard.json",
            "https://example.com/dashboard?_rsc=abc",
            "https://example.com/dashboard.segments/dashboard.segment.rsc",
        ],
    );
}

#[test]
fn next_manifest_roots_follow_asset_prefix_or_observed_mount() {
    let prefixed = scan_html(
        r#"<script id="__NEXT_DATA__" type="application/json">{"buildId":"b1","assetPrefix":"https://cdn.example.com"}</script>"#,
    );
    assert_assets(
        &prefixed,
        &[
            "https://cdn.example.com/_next/static/b1/_buildManifest.js",
            "https://cdn.example.com/_next/static/b1/app-build-manifest.json",
        ],
    );

    let mounted = scan(
        br#"
        <script id="__NEXT_DATA__" type="application/json">{"buildId":"b1"}</script>
        <script src="https://cdn.example.com/docs/_next/static/chunks/app.js"></script>
    "#,
        &url("https://example.com/docs/"),
        DocumentKind::Html,
    );
    assert_assets(
        &mounted,
        &[
            "https://cdn.example.com/docs/_next/static/b1/_buildManifest.js",
            "https://cdn.example.com/docs/_next/static/b1/_ssgManifest.js",
        ],
    );

    let not_next = scan_html(
        r#"<script>window.__APP_DATA__={"buildId":"viteish"};</script><script src="/assets/app.js"></script>"#,
    );
    assert_eq!(not_next.revision, None);
    assert_asset(&not_next, "https://example.com/assets/app.js");
    assert_no_asset_containing(&not_next, "/_next/static/viteish/");
}

#[test]
fn rejects_asset_false_positives() {
    let result = scan_html(
        r#"
        <script src="/_next/static/chunks/instrumentation-abc.js"></script>
        <script>
        // /_next/data/b1/notes.json -- comment, not a real URL
        var path = _next_data_lookup(/_next/data/b1/inline);
        var t={children:x.rsc,rsc:E.rsc};
        var u="/_next/static/chunks/"+n+".rsc";
        var v="/_next/static/chunks/.segment.rsc";
        var w="/_next/static/chunks/"+s+".head.rsc";
        const valid = "/_next/data/b1/dashboard.json";
        </script>
    "#,
    );
    assert_candidate(&result, "/_next/data/b1/dashboard.json");
    for noise in [
        "/_next/data/b1/notes.json",
        "/_next/data/b1/inline",
        "x.rsc",
        "E.rsc",
        ".segment.rsc",
        "/_next/static/chunks/.rsc",
        "/_next/static/chunks/.segment.rsc",
        "/_next/static/chunks/s.head.rsc",
        "instrumentation-abc.js",
    ] {
        assert_no_asset_containing(&result, noise);
        assert!(!result.findings.candidate_map().contains_key(noise));
    }
}

#[test]
fn next_server_actions_reconstruct_routes() {
    for (base, config, kind, expected) in [
        (
            "https://example.com/app/en/dashboard",
            br#"<script id="__NEXT_DATA__" type="application/json">{"buildId":"b1","basePath":"/app","locales":["en","fr"]}</script><form><input name="$ACTION_xyz"></form>"#.as_slice(),
            DocumentKind::Html,
            "/dashboard",
        ),
        (
            "https://example.com/fr/about",
            br#"<script id="__NEXT_DATA__" type="application/json">{"buildId":"b1","locales":["en","fr"]}</script><form><input name="$ACTION_xyz"></form>"#.as_slice(),
            DocumentKind::Html,
            "/about",
        ),
        (
            "https://example.com/(marketing)/about.rsc",
            br#"<script>const a="$ACTION_xyz";</script>"#.as_slice(),
            DocumentKind::Payload,
            "/about",
        ),
    ] {
        assert_api(&scan(config, &url(base), kind), expected);
    }

    let cfg = NextConfig {
        build_id: Some("b1".into()),
        locales: vec!["en".into(), "fr".into()],
        ..Default::default()
    };
    let result = scan_document_with_config(
        br#"<form><input name="$ACTION_xyz"></form>"#,
        &url("https://example.com/fr/about.rsc"),
        DocumentKind::Payload,
        Some(&cfg),
    );
    assert_api(&result, "/about");
}

#[test]
fn manifests_emit_routes_and_manifest_evidence() {
    let build = scan(
        br#"self.__BUILD_MANIFEST=function(s,c){return{"/":["a.js"],"/dashboard":[s],"/about":[c],"/_app":["x"],sortedPages:["/"]}}();"#,
        &url("https://example.com/_next/static/b1/_buildManifest.js"),
        DocumentKind::Manifest,
    );
    assert_routes(&build, &["/", "/dashboard", "/about"]);

    let app = scan(
        br#"{"pages":{"/(marketing)/about/page":["a.js"],"/dashboard/page":["b.js"],"/blog/[slug]/page":["c.js"]}}"#,
        &url("https://example.com/_next/static/b1/app-build-manifest.json"),
        DocumentKind::Manifest,
    );
    assert_routes(&app, &["/about", "/dashboard", "/blog/[slug]"]);
    assert_evidence(&app, "/dashboard", EvidenceKind::Route, Extractor::Manifest);
}

#[test]
fn evidence_keeps_distinct_extractors() {
    let result = scan_html(
        r#"<script>const r="/dashboard";</script><script>self.__next_f.push([1,"0:{\"href\":\"/dashboard\"}"])</script><form><input name="$ACTION_xyz"></form>"#,
    );
    assert_evidence(
        &result,
        "/dashboard",
        EvidenceKind::Route,
        Extractor::Literal,
    );
    assert_evidence(
        &result,
        "/dashboard",
        EvidenceKind::Route,
        Extractor::Flight,
    );
    assert_evidence(&result, "/", EvidenceKind::Api, Extractor::ServerAction);
}

#[test]
fn flight_payloads_add_browser_surface_without_64k_truncation() {
    let result = scan_html(
        r#"<script>self.__next_f.push([1,"0:[\"$\",\"a\",null,{\"href\":\"/profile\",\"action\":\"/api/save\"}]\n"])</script>"#,
    );
    assert_route(&result, "/profile");
    assert!(
        result.findings.route_map().contains_key("/api/save")
            || result.findings.api_map().contains_key("/api/save")
            || result.findings.candidate_map().contains_key("/api/save")
    );

    let mut middle = String::with_capacity(80_000);
    for i in 0..1500 {
        middle.push_str(&format!("\\\"pad_{i}\\\":\\\"x\\\","));
    }
    let html = format!(
        r#"<script>self.__next_f.push([1,"0:{{{middle}\"href\":\"/late-route\"}}\n"])</script>"#
    );
    assert_route(&scan_html(&html), "/late-route");
}

fn scan_html(src: &str) -> hifi::discover::DocumentScan {
    scan(
        src.as_bytes(),
        &url("https://example.com/"),
        DocumentKind::Html,
    )
}

fn scan(bytes: &[u8], base: &Url, kind: DocumentKind) -> hifi::discover::DocumentScan {
    scan_document(bytes, base, kind)
}

fn url(raw: &str) -> Url {
    Url::parse(raw).unwrap()
}

fn assert_asset(result: &hifi::discover::DocumentScan, expected: &str) {
    let assets = asset_urls(result);
    assert!(
        assets.contains(&expected.to_string()),
        "{expected} not in {assets:?}"
    );
}

fn assert_assets(result: &hifi::discover::DocumentScan, expected: &[&str]) {
    for url in expected {
        assert_asset(result, url);
    }
}

fn assert_no_asset_containing(result: &hifi::discover::DocumentScan, needle: &str) {
    let assets = asset_urls(result);
    assert!(
        !assets.iter().any(|url| url.contains(needle)),
        "{needle} unexpectedly found in {assets:?}"
    );
}

fn assert_api(result: &hifi::discover::DocumentScan, url: &str) {
    assert!(
        result.findings.api_map().contains_key(url),
        "{url} not in {:?}",
        result.findings.api_map().keys().collect::<Vec<_>>()
    );
}

fn assert_candidate(result: &hifi::discover::DocumentScan, url: &str) {
    assert!(
        result.findings.candidate_map().contains_key(url),
        "{url} not in {:?}",
        result.findings.candidate_map().keys().collect::<Vec<_>>()
    );
}

fn assert_route(result: &hifi::discover::DocumentScan, url: &str) {
    assert!(
        result.findings.route_map().contains_key(url),
        "{url} not in {:?}",
        result.findings.route_map().keys().collect::<Vec<_>>()
    );
}

fn assert_routes(result: &hifi::discover::DocumentScan, routes: &[&str]) {
    for route in routes {
        assert_route(result, route);
    }
}

fn assert_evidence(
    result: &hifi::discover::DocumentScan,
    url: &str,
    kind: EvidenceKind,
    extractor: Extractor,
) {
    assert!(
        result
            .findings
            .evidence
            .iter()
            .any(|e| e.url == url && e.kind == kind && e.extractor == extractor),
        "missing {kind:?}/{extractor:?} evidence for {url}"
    );
}

fn asset_urls(result: &hifi::discover::DocumentScan) -> Vec<String> {
    result
        .assets
        .iter()
        .map(|asset| asset.url.as_str().to_string())
        .collect()
}
