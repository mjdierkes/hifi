use hifi::scan::{scan, ApiMap};

#[test]
fn finds_fetch_url_and_shape() {
    let mut apis = ApiMap::default();
    scan(
        br#"fetch("/api/users", {method:"POST", body:x, headers:{"Content-Type":"application/json"}})"#,
        &mut apis,
    );

    let v = serde_json::to_value(&apis["/api/users"]).unwrap();
    assert_eq!(v["methods"], serde_json::json!(["POST"]));
    assert_eq!(v["has_body"], true);
    assert_eq!(v["has_headers"], true);
    assert_eq!(v["content_types"], serde_json::json!(["application/json"]));
}

#[test]
fn rejects_asset_urls() {
    let mut apis = ApiMap::default();
    scan(
        br#"fetch("/images/LOGO.PNG?cache=1"); fetch("/api/users")"#,
        &mut apis,
    );

    assert!(!apis.contains_key("/images/LOGO.PNG?cache=1"));
    assert!(apis.contains_key("/api/users"));
}
