use hifi::scan::{scan_endpoints, ScanResult};
#[rustfmt::skip]
const API_CASES: &[(&str, &str, &str, &str)] = &[
    (r#"fetch("/api/users", {method:"POST", body:x, headers:{"Content-Type":"application/json"}})"#, "/api/users", "POST", "body,headers,json"),
    (r#"fetch("/api/users?team=red&page=1", { method: "post", body: new URLSearchParams() })"#, "/api/users", "POST", "body,urlencoded,query"),
    (r#"fetch("/api/ping", { method: "HEAD" }); fetch("/api/cors", { method: "OPTIONS" });"#, "/api/ping", "HEAD", ""),
    (r#"axios.post(`/machines/${id}/image`, { name: imageName })"#, "/machines/{dynamic}/image", "POST", "body,json"),
    (r#"ky.get(`/server-types?provider=${provider}`)"#, "/server-types", "GET", "query"),
];

#[test]
fn api_shapes() {
    for &(src, url, methods, flags) in API_CASES {
        let result = scan(src);
        let apis = result.api_map();
        let shape = &apis[url];
        assert_eq!(shape.methods_csv(), methods, "{url}");
        assert_eq!(shape.flags_csv(), flags, "{url}");
    }
}

#[test]
fn ignores_non_urls_and_assets() {
    let result =
        scan(r#"map.get("session_id"); fetch("/images/LOGO.PNG?cache=1"); fetch("/api/users")"#);
    let apis = result.api_map();
    assert_eq!(apis.len(), 1);
    assert!(apis.contains_key("/api/users"));
}

#[test]
fn candidates_cover_strings_templates_and_raw_literals() {
    let result = scan(
        r#"
        const routes={users:"/api/users",gql:"/graphql"};
        let full="https://x.test/api/team";
        fetch(`/api/users/${id}`); fetch(`/api/${team}/settings`);
        self.__next_f.push([1,/api/raw,0]);
    "#,
    );
    let candidates = result.candidate_map();
    for url in [
        "/api/users",
        "/graphql",
        "https://x.test/api/team",
        "/api/raw",
    ] {
        assert!(candidates.contains_key(url), "{url}");
    }
    assert!(!candidates.contains_key("/api/users/"));
}

#[test]
fn routes_and_api_candidates_are_classified_separately() {
    let result = scan(
        r#"
        fetch("/api/users", {method:"POST", headers:{"Content-Type":"application/json"}});
        const route=`/api/team/${id}`;
        router.push("/dashboard");
        const a={href:"/pricing",pathname:'/blog/${slug}'};
        router.replace(`/settings/${tab}`);
        const asset="/images/logo.png";
    "#,
    );
    let routes = result.route_map();
    for url in [
        "/dashboard",
        "/pricing",
        "/blog/{dynamic}",
        "/settings/{dynamic}",
    ] {
        assert!(routes.contains_key(url), "{url}");
    }
    assert!(result.candidate_map().contains_key("/api/team/{dynamic}"));
    assert!(!routes.contains_key("/api/users"));
    assert!(!routes.contains_key("/images/logo.png"));
}

#[test]
fn unresolved_leading_template_base_still_preserves_path() {
    let result = scan(r#"fetch(`${base}/api/admin`);"#);

    let apis = result.api_map();
    assert!(!apis.contains_key("/api/admin"));
    assert!(!apis.contains_key("{dynamic}/api/admin"));
}

#[test]
fn url_consisting_only_of_dynamic_segments_is_ignored() {
    // When the entire URL is interpolation (`/${id}`), the resolved literal
    // collapses to `/{dynamic}` which carries no information.
    let result = scan(
        r#"
        const u = `/${id}`;
        fetch(u, {method:"GET"});
    "#,
    );
    assert!(!result.api_map().contains_key("/{dynamic}"));
    assert!(!result.candidate_map().contains_key("/{dynamic}"));
    assert!(!result.route_map().contains_key("/{dynamic}"));
}

#[test]
fn wasm_assets_are_not_endpoints() {
    let result = scan(
        r#"
        const u = "/assets/rnnoise.wasm";
        fetch(u);
    "#,
    );
    assert!(!result.api_map().contains_key("/assets/rnnoise.wasm"));
}

#[test]
fn percent_encoded_svg_does_not_become_a_route() {
    // Reproduces a real false-positive from Next.js's getImageBlurSvg, which
    // emits literals like "...%3E%3CfeGaussianBlur stdDeviation='20'/%3E..."
    let result = scan(
        r#"
        let svg = "%3Csvg xmlns='http://www.w3.org/2000/svg' %3E%3Cfilter id='b'%3E%3CfeGaussianBlur stdDeviation='20'/%3E%3C/filter%3E%3C/svg%3E";
        router.push("/dashboard");
    "#,
    );
    let routes = result.route_map();
    assert!(routes.contains_key("/dashboard"));
    for noise in [
        "/%3E%3CfeGaussianBlur",
        "/%3E%3C/filter%3E",
        "/%3E%3C/svg%3E",
    ] {
        assert!(
            !routes.contains_key(noise),
            "encoded-markup leak became a route: {noise}"
        );
    }
}

fn scan(src: &str) -> ScanResult {
    scan_endpoints(src.as_bytes())
}
