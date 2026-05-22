use hifi::{
    scan_document, scan_document_with_config, DocumentKind, DocumentScan, EvidenceKind, Extractor,
    NextConfig,
};
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
fn lightweight_framework_support_detects_assets_payloads_and_labels() {
    let nuxt = scan_html(
        r#"
        <script type="application/json" id="__NUXT_DATA__">[{}]</script>
        <script src="/_nuxt/app.123.js"></script>
        <script>const payload="/products/_payload.json"; import("_nuxt/chunk.456.js")</script>
    "#,
    );
    assert_eq!(nuxt.framework_config.label().as_deref(), Some("Nuxt"));
    assert_assets(
        &nuxt,
        &[
            "https://example.com/_nuxt/app.123.js",
            "https://example.com/products/_payload.json",
            "https://example.com/_nuxt/chunk.456.js",
        ],
    );
    assert_candidate(&nuxt, "/products/_payload.json");

    let svelte = scan_html(
        r#"
        <div data-sveltekit-preload-data="hover"></div>
        <script src="/_app/immutable/entry/start.abc.js"></script>
        <script>const data="/shop/__data.json?x-sveltekit-invalidated=1"; import("_app/immutable/chunks/page.def.js")</script>
    "#,
    );
    assert_eq!(
        svelte.framework_config.label().as_deref(),
        Some("SvelteKit")
    );
    assert_assets(
        &svelte,
        &[
            "https://example.com/_app/immutable/entry/start.abc.js",
            "https://example.com/shop/__data.json?x-sveltekit-invalidated=1",
            "https://example.com/_app/immutable/chunks/page.def.js",
        ],
    );

    let astro = scan_html(
        r#"
        <astro-island component-url="/_astro/Product.abc.js"></astro-island>
        <script>const action="/_actions/add-to-cart"; import("_astro/client.def.js")</script>
    "#,
    );
    assert_eq!(astro.framework_config.label().as_deref(), Some("Astro"));
    assert_asset(&astro, "https://example.com/_actions/add-to-cart");
    assert_no_asset_containing(&astro, "/_astro/client.def.js");

    let remix = scan_html(
        r#"
        <script>window.__remixContext={}; const data="/products?_data=routes/products"; import("build/routes/products-abc.js")</script>
    "#,
    );
    assert_eq!(remix.framework_config.label().as_deref(), Some("Remix"));
    assert_assets(
        &remix,
        &[
            "https://example.com/products?_data=routes/products",
            "https://example.com/build/routes/products-abc.js",
        ],
    );
}

#[test]
fn framework_80_20_expansion_follows_manifests_payloads_and_islands() {
    let nuxt = scan_html(
        r#"
        <script id="__NUXT_DATA__">[{}]</script>
        <script>const meta="/_nuxt/builds/meta/abc.json"; const api="/api/catalog";</script>
    "#,
    );
    assert_asset(&nuxt, "https://example.com/_nuxt/builds/meta/abc.json");
    assert_evidence(
        &nuxt,
        "/api/catalog",
        EvidenceKind::Candidate,
        Extractor::NuxtPayload,
    );

    let nuxt_payload = scan(
        br#"{"state":{"endpoint":"/api/products"}}"#,
        &url("https://example.com/products/_payload.json"),
        DocumentKind::Payload,
    );
    assert_route(&nuxt_payload, "/products");
    assert_evidence(
        &nuxt_payload,
        "/api/products",
        EvidenceKind::Candidate,
        Extractor::NuxtPayload,
    );

    let svelte = scan_html(
        r#"
        <script>window.__sveltekit_x={}; const node="nodes/2.abc.js"; const chunk="chunks/api.def.js";</script>
    "#,
    );
    assert_assets(
        &svelte,
        &[
            "https://example.com/_app/immutable/nodes/2.abc.js",
            "https://example.com/_app/immutable/chunks/api.def.js",
        ],
    );

    let remix = scan_html(
        r#"
        <script>window.__remixContext={manifest:{routes:{x:{module:"routes/products.abc.js"}}}};</script>
    "#,
    );
    assert_asset(&remix, "https://example.com/build/routes/products.abc.js");

    let astro = scan_html(
        r#"
        <astro-island component-url="/_astro/Product.abc.js" renderer-url="/_astro/client.def.js"></astro-island>
        <script>const endpoint="/_actions/cart.add";</script>
    "#,
    );
    assert_asset(&astro, "https://example.com/_astro/Product.abc.js");
    assert_api(&astro, "/_actions/cart.add");
    assert_evidence(
        &astro,
        "/_actions/cart.add",
        EvidenceKind::Api,
        Extractor::AstroIsland,
    );
}

#[test]
fn nuxt_deep_support_seeds_build_metadata_and_relative_chunks() {
    let nuxt = scan(
        br#"
        <script id="__NUXT_DATA__">[{"buildId":"b123"}]</script>
        <script>window.__NUXT__={config:{app:{baseURL:"/docs/",buildAssetsDir:"/_nuxt/",cdnURL:"https://cdn.example.com"}}}</script>
        <script>
        const page="pages/products.abc.js";
        const chunk="chunks/catalog.def.js";
        const component="components/Product.ghi.js";
        const island="/__nuxt_island/product-card.json";
        const payload="/docs/products/_payload.json";
        const api="/api/nuxt-deep";
        </script>
    "#,
        &url("https://example.com/docs/"),
        DocumentKind::Html,
    );
    assert_eq!(nuxt.framework_config.label().as_deref(), Some("Nuxt"));
    assert_assets(
        &nuxt,
        &[
            "https://cdn.example.com/docs/_nuxt/builds/meta/b123.json",
            "https://cdn.example.com/docs/_nuxt/builds/latest.json",
            "https://example.com/_nuxt/pages/products.abc.js",
            "https://example.com/_nuxt/chunks/catalog.def.js",
            "https://example.com/_nuxt/components/Product.ghi.js",
            "https://example.com/__nuxt_island/product-card.json",
            "https://example.com/docs/products/_payload.json",
        ],
    );
    assert_api(&nuxt, "/__nuxt_island/product-card.json");
    assert_evidence(
        &nuxt,
        "/api/nuxt-deep",
        EvidenceKind::Candidate,
        Extractor::NuxtPayload,
    );
}

#[test]
fn nuxt_legacy_and_payload_js_emit_routes_and_apis() {
    let legacy = scan_html(
        r#"
        <script>window.__NUXT__={serverRendered:true,routePath:"/legacy",staticAssetsBase:"/_nuxt/static/abc",config:{endpoint:"/api/legacy"}}</script>
        <script>const payload="/legacy/payload.js"; const manifest="/_nuxt/routes.json";</script>
    "#,
    );
    assert_eq!(legacy.framework_config.label().as_deref(), Some("Nuxt"));
    assert_assets(
        &legacy,
        &[
            "https://example.com/legacy/payload.js",
            "https://example.com/_nuxt/routes.json",
        ],
    );
    assert_evidence(
        &legacy,
        "/legacy",
        EvidenceKind::Route,
        Extractor::NuxtPayload,
    );
    assert_evidence(
        &legacy,
        "/api/legacy",
        EvidenceKind::Candidate,
        Extractor::NuxtPayload,
    );

    let payload = scan(
        br#"export default {"path":"/payload-page","api":"/api/payload-js","prerenderedRoutes":["/payload-prerender"]}"#,
        &url("https://example.com/payload-page/payload.js"),
        DocumentKind::Payload,
    );
    assert_route(&payload, "/payload-page");
    assert_evidence(
        &payload,
        "/payload-prerender",
        EvidenceKind::Route,
        Extractor::NuxtPayload,
    );
    assert_evidence(
        &payload,
        "/api/payload-js",
        EvidenceKind::Candidate,
        Extractor::NuxtPayload,
    );

    let manifest = scan(
        br#"{"routes":["/shop","/blog/[slug]"],"prerenderedRoutes":["/pricing"],"/nested":{"path":"/nested"}}"#,
        &url("https://example.com/_nuxt/routes.json"),
        DocumentKind::Manifest,
    );
    for route in ["/shop", "/blog/[slug]", "/pricing", "/nested"] {
        assert_evidence(
            &manifest,
            route,
            EvidenceKind::Route,
            Extractor::NuxtPayload,
        );
    }
}

#[test]
fn nuxt_endpoint_maps_promote_api_evidence() {
    let result = scan_html(
        r#"
        <script id="__NUXT_DATA__">[{}]</script>
        <script>
        window.__NUXT__={config:{public:{
          endpoints:{
            player:"/api/players/player",
            search:"/api/players/search",
            flags:"https://edge.api.flagsmith.com/api/v1/"
          },
          mediaUrl:"/images/logo.png"
        }}}
        </script>
    "#,
    );
    for api in [
        "/api/players/player",
        "/api/players/search",
        "https://edge.api.flagsmith.com/api/v1/",
    ] {
        assert_evidence(&result, api, EvidenceKind::Api, Extractor::NuxtPayload);
    }
    assert_no_api(&result, "/images/logo.png");
}

#[test]
fn sveltekit_deep_support_seeds_version_data_routes_and_actions() {
    let result = scan(
        br#"
        <script>window.__sveltekit_abc={};</script>
        <script>
        const manifest={
          routes:[
            {id:"/products/[slug]", pattern:/^\/products\/([^/]+?)\/?$/, page:{leaf:2}},
            {route:"/account/settings", page:{leaf:3}}
          ],
          nodes:[()=>import("nodes/2.abc.js"),()=>import("chunks/settings.def.js")]
        };
        const api="/api/sveltekit-products";
        const namedAction="?/save";
        const dataAction="/cart/__data.json?/add";
        </script>
    "#,
        &url("https://example.com/account/settings"),
        DocumentKind::Html,
    );
    assert_eq!(
        result.framework_config.label().as_deref(),
        Some("SvelteKit")
    );
    assert_assets(
        &result,
        &[
            "https://example.com/_app/version.json",
            "https://example.com/products/[slug]/__data.json",
            "https://example.com/account/settings/__data.json",
            "https://example.com/_app/immutable/nodes/2.abc.js",
            "https://example.com/_app/immutable/chunks/settings.def.js",
        ],
    );
    assert_evidence(
        &result,
        "/products/[slug]",
        EvidenceKind::Route,
        Extractor::SvelteKitData,
    );
    assert_evidence(
        &result,
        "/account/settings",
        EvidenceKind::Route,
        Extractor::SvelteKitData,
    );
    assert_evidence(
        &result,
        "/api/sveltekit-products",
        EvidenceKind::Candidate,
        Extractor::SvelteKitData,
    );
    assert_evidence(
        &result,
        "/account/settings",
        EvidenceKind::Api,
        Extractor::SvelteKitData,
    );
    assert_evidence(
        &result,
        "/cart",
        EvidenceKind::Api,
        Extractor::SvelteKitData,
    );
}

#[test]
fn sveltekit_payloads_map_back_to_routes_and_dependencies() {
    let result = scan(
        br#"{"type":"data","nodes":[{"route":"/shop","uses":{"dependencies":["/api/products","/images/logo.png"]}}]}"#,
        &url("https://example.com/shop/__data.json"),
        DocumentKind::Payload,
    );
    assert_route(&result, "/shop");
    assert_evidence(
        &result,
        "/api/products",
        EvidenceKind::Candidate,
        Extractor::SvelteKitData,
    );
    assert_evidence(
        &result,
        "/api/products",
        EvidenceKind::Api,
        Extractor::SvelteKitData,
    );
    assert_no_api(&result, "/images/logo.png");
}

#[test]
fn sveltekit_minified_patterns_and_node_assets_are_recovered() {
    let result = scan(
        br#"
        window.__sveltekit_x={};
        const route={pattern:/^\/blog\/([^/]+?)\/comments\/([^/]+?)\/?$/,params:["slug","comment"]};
        const asset="assets/widget.abc.js";
        const node={uses:{dependencies:["/graphql?query=Post","/trpc/posts.byId?id=1"]}};
        "#,
        &url("https://example.com/_app/immutable/nodes/5.abc.js"),
        DocumentKind::Script,
    );
    assert_assets(
        &result,
        &[
            "https://example.com/_app/immutable/assets/widget.abc.js",
            "https://example.com/blog/[slug]/comments/[comment]/__data.json",
        ],
    );
    assert_evidence(
        &result,
        "/blog/[slug]/comments/[comment]",
        EvidenceKind::Route,
        Extractor::SvelteKitData,
    );
    assert_evidence(
        &result,
        "/graphql",
        EvidenceKind::Api,
        Extractor::SvelteKitData,
    );
    assert_evidence(
        &result,
        "/trpc/posts.byId",
        EvidenceKind::Api,
        Extractor::SvelteKitData,
    );
}

#[test]
fn sveltekit_custom_app_dir_and_base_paths_are_respected() {
    let result = scan(
        br#"
        <script>window.__sveltekit_custom={base:"/docs",appDir:"_client"};</script>
        <script src="/docs/_client/immutable/entry/start.abc.js"></script>
        <script>
        const route={id:"/guide/[slug]"};
        const node="nodes/3.node.js";
        const chunk="chunks/guide.chunk.js";
        </script>
    "#,
        &url("https://example.com/docs/guide/intro"),
        DocumentKind::Html,
    );
    assert_assets(
        &result,
        &[
            "https://example.com/docs/_client/immutable/entry/start.abc.js",
            "https://example.com/docs/_client/immutable/nodes/3.node.js",
            "https://example.com/docs/_client/immutable/chunks/guide.chunk.js",
            "https://example.com/docs/_client/version.json",
            "https://example.com/docs/guide/[slug]/__data.json",
        ],
    );
    assert_evidence(
        &result,
        "/guide/[slug]",
        EvidenceKind::Route,
        Extractor::SvelteKitData,
    );

    let node = scan(
        br#"window.__sveltekit_custom={}; const dep="chunks/child.node.js"; const route={id:"/node-route"};"#,
        &url("https://example.com/docs/_client/immutable/nodes/3.node.js"),
        DocumentKind::Script,
    );
    assert_assets(
        &node,
        &[
            "https://example.com/docs/_client/immutable/chunks/child.node.js",
            "https://example.com/node-route/__data.json",
        ],
    );
}

#[test]
fn nuxt_runtime_config_bases_promote_relative_endpoints() {
    let result = scan_html(
        r#"
        <script id="__NUXT_DATA__">[{}]</script>
        <script>
        window.__NUXT__={config:{public:{
          apiBase:"/api",
          endpoints:{
            player:"players/player",
            standings:"schedules/standings",
            image:"images/logo"
          }
        }}}
        </script>
    "#,
    );
    for api in ["/api/players/player", "/api/schedules/standings"] {
        assert_evidence(&result, api, EvidenceKind::Api, Extractor::NuxtPayload);
    }
    assert_no_api(&result, "/api/images/logo");
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

fn scan_html(src: &str) -> DocumentScan {
    scan(
        src.as_bytes(),
        &url("https://example.com/"),
        DocumentKind::Html,
    )
}

fn scan(bytes: &[u8], base: &Url, kind: DocumentKind) -> DocumentScan {
    scan_document(bytes, base, kind)
}

fn url(raw: &str) -> Url {
    Url::parse(raw).unwrap()
}

fn assert_asset(result: &DocumentScan, expected: &str) {
    let assets = asset_urls(result);
    assert!(
        assets.contains(&expected.to_string()),
        "{expected} not in {assets:?}"
    );
}

fn assert_assets(result: &DocumentScan, expected: &[&str]) {
    for url in expected {
        assert_asset(result, url);
    }
}

fn assert_no_asset_containing(result: &DocumentScan, needle: &str) {
    let assets = asset_urls(result);
    assert!(
        !assets.iter().any(|url| url.contains(needle)),
        "{needle} unexpectedly found in {assets:?}"
    );
}

fn assert_api(result: &DocumentScan, url: &str) {
    assert!(
        result.findings.api_map().contains_key(url),
        "{url} not in {:?}",
        result.findings.api_map().keys().collect::<Vec<_>>()
    );
}

fn assert_no_api(result: &DocumentScan, url: &str) {
    assert!(
        !result.findings.api_map().contains_key(url),
        "{url} unexpectedly in {:?}",
        result.findings.api_map().keys().collect::<Vec<_>>()
    );
}

fn assert_candidate(result: &DocumentScan, url: &str) {
    assert!(
        result.findings.candidate_map().contains_key(url),
        "{url} not in {:?}",
        result.findings.candidate_map().keys().collect::<Vec<_>>()
    );
}

fn assert_route(result: &DocumentScan, url: &str) {
    assert!(
        result.findings.route_map().contains_key(url),
        "{url} not in {:?}",
        result.findings.route_map().keys().collect::<Vec<_>>()
    );
}

fn assert_routes(result: &DocumentScan, routes: &[&str]) {
    for route in routes {
        assert_route(result, route);
    }
}

fn assert_evidence(result: &DocumentScan, url: &str, kind: EvidenceKind, extractor: Extractor) {
    assert!(
        result
            .findings
            .evidence
            .iter()
            .any(|e| e.url == url && e.kind == kind && e.extractor == extractor),
        "missing {kind:?}/{extractor:?} evidence for {url}"
    );
}

fn asset_urls(result: &DocumentScan) -> Vec<String> {
    result
        .assets
        .iter()
        .map(|asset| asset.url.as_str().to_string())
        .collect()
}
