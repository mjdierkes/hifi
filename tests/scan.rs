use hifi::scan::{scan_endpoints, ScanResult};
use serde_json::Value;

#[rustfmt::skip]
const API_CASES: &[(&str, &str, &str, &str)] = &[
    (r#"fetch("/api/users", {method:"POST", body:x, headers:{"Content-Type":"application/json"}})"#, "/api/users", "POST", "body,headers,json"),
    (r#"fetch("/api/users?team=red&page=1", { method: "post", body: new URLSearchParams() })"#, "/api/users", "POST", "body,urlencoded,query"),
    (r#"axios({ url: "/api/object", method: "PUT" }); client({endpoint:'/api/endpoint',method:'DELETE'});"#, "/api/object", "PUT", ""),
    (r#"axios({ url: "/api/object", method: "PUT" }); client({endpoint:'/api/endpoint',method:'DELETE'});"#, "/api/endpoint", "DELETE", ""),
    (r#"fetch("/api/ping", { method: "HEAD" }); fetch("/api/cors", { method: "OPTIONS" });"#, "/api/ping", "HEAD", ""),
    (r#"useSWR("/api/profile", fetcher)"#, "/api/profile", "GET", ""),
    (r#"new Request("/api/upload", {method:"POST"})"#, "/api/upload", "POST", ""),
    (r#"api.post(`/machines/${id}/image`, { name: imageName })"#, "/machines/{dynamic}/image", "POST", "body,json,body-shape"),
    (r#"api.get(`/server-types?provider=${provider}`)"#, "/server-types", "GET", "query"),
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
fn body_shape_records_static_object_keys() {
    let result = scan(r#"api.patch("/account/password", { current_password, new_password })"#);
    let json = serde_json::to_value(&result.apis["/account/password"]).unwrap();

    assert_eq!(
        json.get("body_params").and_then(Value::as_array).unwrap(),
        &vec![
            Value::String("current_password".into()),
            Value::String("new_password".into())
        ]
    );
}

#[test]
fn candidates_cover_strings_templates_and_raw_literals() {
    let result = scan(
        r#"
        const routes={users:"/api/users",gql:"/graphql"};
        let full="https://x.test/api/team";
        fetch(`/api/users/${id}`); fetch(`${base}/api/admin`); fetch(`/api/${team}/settings`);
        self.__next_f.push([1,/api/raw,0]);
    "#,
    );
    for url in [
        "/api/users",
        "/graphql",
        "https://x.test/api/team",
        "/api/users/{dynamic}",
        "/api/admin",
        "/api/{dynamic}/settings",
        "/api/raw",
    ] {
        assert!(result.candidates.contains_key(url), "{url}");
    }
    assert!(!result.candidates.contains_key("/api/users/"));
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
    for url in [
        "/dashboard",
        "/pricing",
        "/blog/{dynamic}",
        "/settings/{dynamic}",
    ] {
        assert!(result.routes.contains_key(url), "{url}");
    }
    assert!(result.candidates.contains_key("/api/team/{dynamic}"));
    assert!(!result.routes.contains_key("/api/users"));
    assert!(!result.routes.contains_key("/images/logo.png"));
}

fn scan(src: &str) -> ScanResult {
    scan_endpoints(src.as_bytes())
}
