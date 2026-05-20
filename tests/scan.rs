use hifi::scan::{scan_document, ScanResult};
use url::Url;

#[rustfmt::skip]
const API_CASES: &[(&str, &str, &str, &str)] = &[
    (r#"fetch("/api/users", {method:"POST", body:x, headers:{"Content-Type":"application/json"}})"#, "/api/users", "POST", "body,headers,json"),
    (r#"fetch("/api/users?team=red&page=1", { method: "post", body: new URLSearchParams() })"#, "/api/users?team=red&page=1", "POST", "body,urlencoded,query"),
    (r#"axios({ url: "/api/object", method: "PUT" }); client({endpoint:'/api/endpoint',method:'DELETE'});"#, "/api/object", "PUT", ""),
    (r#"axios({ url: "/api/object", method: "PUT" }); client({endpoint:'/api/endpoint',method:'DELETE'});"#, "/api/endpoint", "DELETE", ""),
    (r#"fetch("/api/ping", { method: "HEAD" }); fetch("/api/cors", { method: "OPTIONS" });"#, "/api/ping", "HEAD", ""),
    (r#"useSWR("/api/profile", fetcher)"#, "/api/profile", "GET", ""),
    (r#"new Request("/api/upload", {method:"POST"})"#, "/api/upload", "POST", ""),
];

#[test]
fn api_shapes() {
    for &(src, url, methods, flags) in API_CASES {
        let result = scan(src);
        let shape = &result.apis[url];
        assert_eq!(shape.methods_csv(), methods, "{url}");
        assert_eq!(shape.flags_csv(), flags, "{url}");
    }
}

#[test]
fn ignores_non_urls_and_assets() {
    let result =
        scan(r#"map.get("session_id"); fetch("/images/LOGO.PNG?cache=1"); fetch("/api/users")"#);
    assert_eq!(result.apis.len(), 1);
    assert!(result.apis.contains_key("/api/users"));
}

#[test]
fn candidates_cover_strings_templates_and_raw_literals() {
    let result = scan(
        r#"
        const routes={users:"/api/users",gql:"/graphql",data:"/_next/data/b1/users.json"};
        let full="https://x.test/api/team";
        fetch(`/api/users/${id}`); fetch(`${base}/api/admin`); fetch(`/api/${team}/settings`);
        self.__next_f.push([1,/api/raw,0,/_next/data/b1/raw.json]);
    "#,
    );
    for url in [
        "/api/users",
        "/graphql",
        "/_next/data/b1/users.json",
        "https://x.test/api/team",
        "/api/users/{dynamic}",
        "/api/admin",
        "/api/{dynamic}/settings",
        "/api/raw",
        "/_next/data/b1/raw.json",
    ] {
        assert!(result.candidates.contains_key(url), "{url}");
    }
    assert!(!result.candidates.contains_key("/api/users/"));
}

#[test]
fn routes_and_chunks_are_classified_separately() {
    let result = scan(
        r#"
        fetch("/api/users", {method:"POST", headers:{"Content-Type":"application/json"}});
        const route=`/api/team/${id}`;
        router.push("/dashboard");
        const a={href:"/pricing",pathname:'/blog/${slug}'};
        router.replace(`/settings/${tab}`);
        const asset="/images/logo.png";
        self.__next_f.push([1,/_next/data/b1/raw.json]);
        e.u=function(e){return"static/chunks/app/dashboard-deadbeef.js"};
        <script src=/_next/static/chunks/app/page-123.js async></script>
        <script src="https://cdn.example.com/_next/static/chunks/app/users-f00d.js"></script>
    "#,
    );
    for url in [
        "/dashboard",
        "/pricing",
        "/blog/{dynamic}",
        "/settings/{dynamic}",
    ] {
        assert!(result.routes.contains_key(url), "{url}");
    }
    for url in ["/api/team/{dynamic}", "/_next/data/b1/raw.json"] {
        assert!(result.candidates.contains_key(url), "{url}");
    }
    assert!(!result.routes.contains_key("/api/users"));
    assert!(!result.routes.contains_key("/images/logo.png"));
    let refs = result
        .refs
        .iter()
        .map(|url| url.as_str())
        .collect::<Vec<_>>();
    assert!(refs
        .iter()
        .any(|url| url.ends_with("app/dashboard-deadbeef.js")));
    assert!(refs.contains(&"https://example.com/_next/static/chunks/app/page-123.js"));
    assert!(refs.contains(&"https://cdn.example.com/_next/static/chunks/app/users-f00d.js"));
}

fn scan(src: &str) -> ScanResult {
    scan_document(
        src.as_bytes(),
        &Url::parse("https://example.com/_next/static/chunks/app/main.js").unwrap(),
    )
}
