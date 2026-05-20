use hifi::scan::{
    scan, scan_candidates, scan_document, ApiMap, CandidateMap, ScanResult,
    StreamingDocumentScanner,
};
use serde_json::Value;
use url::Url;

#[test]
fn finds_fetch_url_and_shape() {
    let apis = scanned(
        br#"fetch("/api/users", {method:"POST", body:x, headers:{"Content-Type":"application/json"}})"#,
    );

    let shape = &apis["/api/users"];
    assert_eq!(shape.methods_csv(), "POST");
    assert_eq!(shape.flags_csv(), "body,headers,json");
}

#[test]
fn finds_spaced_lowercase_methods_and_query_params() {
    let apis = scanned(
        br#"fetch("/api/users?team=red&page=1", { method: "post", body: new URLSearchParams() })"#,
    );

    let shape = &apis["/api/users?team=red&page=1"];
    assert_eq!(shape.methods_csv(), "POST");
    assert_eq!(shape.flags_csv(), "body,urlencoded,query");
}

#[test]
fn finds_endpoint_and_object_config_urls() {
    let apis = scanned(
        br#"axios({ url: "/api/object", method: "PUT" }); client({endpoint:'/api/endpoint',method:'DELETE'});"#,
    );

    assert_eq!(apis["/api/object"].methods_csv(), "PUT");
    assert_eq!(apis["/api/endpoint"].methods_csv(), "DELETE");
}

#[test]
fn finds_head_and_options_methods() {
    let apis = scanned(
        br#"fetch("/api/ping", { method: "HEAD" }); fetch("/api/cors", { method: "OPTIONS" });"#,
    );

    assert_eq!(apis["/api/ping"].methods_csv(), "HEAD");
    assert_eq!(apis["/api/cors"].methods_csv(), "OPTIONS");
}

#[test]
fn finds_useswr_calls() {
    let apis = scanned(br#"useSWR("/api/profile", fetcher)"#);
    assert!(apis.contains_key("/api/profile"));
}

#[test]
fn finds_new_request_urls() {
    let apis = scanned(br#"new Request("/api/upload", {method:"POST"})"#);
    assert_eq!(apis["/api/upload"].methods_csv(), "POST");
}

#[test]
fn ignores_non_url_get_post_calls() {
    let apis = scanned(br#"map.get("session_id"); arr.get(0); set.delete("token");"#);
    assert!(apis.is_empty());
}

#[test]
fn rejects_asset_urls() {
    let apis = scanned(br#"fetch("/images/LOGO.PNG?cache=1"); fetch("/api/users")"#);

    assert!(!apis.contains_key("/images/LOGO.PNG?cache=1"));
    assert!(apis.contains_key("/api/users"));
}

#[test]
fn finds_api_candidate_literals_outside_calls() {
    let mut candidates = CandidateMap::default();
    scan_candidates(
        br#"const routes={users:"/api/users",gql:"/graphql",data:"/_next/data/b1/users.json"}; let full="https://x.test/api/team";"#,
        &mut candidates,
    );

    assert!(candidates.contains_key("/api/users"));
    assert!(candidates.contains_key("/graphql"));
    assert!(candidates.contains_key("/_next/data/b1/users.json"));
    assert!(candidates.contains_key("https://x.test/api/team"));
}

#[test]
fn finds_api_candidate_template_fragments() {
    let mut candidates = CandidateMap::default();
    scan_candidates(
        br#"fetch(`/api/users/${id}`); fetch(`${base}/api/admin`); fetch(`/api/${team}/settings`)"#,
        &mut candidates,
    );

    assert!(candidates.contains_key("/api/users/{dynamic}"));
    assert!(!candidates.contains_key("/api/users/"));
    assert!(candidates.contains_key("/api/admin"));
    assert!(candidates.contains_key("/api/{dynamic}/settings"));
}

#[test]
fn finds_unquoted_api_candidates() {
    let mut candidates = CandidateMap::default();
    scan_candidates(
        br#"self.__next_f.push([1,/api/raw,0,/_next/data/b1/raw.json])"#,
        &mut candidates,
    );

    assert!(candidates.contains_key("/api/raw"));
    assert!(candidates.contains_key("/_next/data/b1/raw.json"));
}

#[test]
fn fused_scan_collects_apis_candidates_and_chunk_refs() {
    let base = Url::parse("https://example.com/_next/static/chunks/app/main.js").unwrap();
    let result = scan_document(
        br#"
            fetch("/api/users", {method:"POST", headers:{"Content-Type":"application/json"}});
            const route=`/api/team/${id}`;
            router.push("/dashboard");
            const href="/team/${slug}";
            self.__next_f.push([1,/_next/data/b1/raw.json]);
            e.u=function(e){return"static/chunks/app/dashboard-deadbeef.js"};
        "#,
        &base,
    );

    assert_eq!(result.apis["/api/users"].methods_csv(), "POST");
    assert_eq!(result.apis["/api/users"].flags_csv(), "headers,json");
    assert!(result.candidates.contains_key("/api/team/{dynamic}"));
    assert!(result.candidates.contains_key("/_next/data/b1/raw.json"));
    assert!(result.routes.contains_key("/dashboard"));
    assert!(result.routes.contains_key("/team/{dynamic}"));
    assert!(result
        .refs
        .iter()
        .any(|url| url.as_str().ends_with("app/dashboard-deadbeef.js")));
}

#[test]
fn finds_client_routes_without_mixing_api_candidates() {
    let base = Url::parse("https://example.com/_next/static/chunks/app/main.js").unwrap();
    let result = scan_document(
        br#"
            const a={href:"/pricing",pathname:'/blog/${slug}'};
            router.replace(`/settings/${tab}`);
            const api="/api/users";
            const asset="/images/logo.png";
        "#,
        &base,
    );

    assert!(result.routes.contains_key("/pricing"));
    assert!(result.routes.contains_key("/blog/{dynamic}"));
    assert!(result.routes.contains_key("/settings/{dynamic}"));
    assert!(!result.routes.contains_key("/api/users"));
    assert!(!result.routes.contains_key("/images/logo.png"));
}

#[test]
fn streaming_scan_matches_full_scan_across_split_boundaries() {
    let base = Url::parse("https://example.com/_next/static/chunks/app/main.js").unwrap();
    let body = br#"
        fetch("/api/users", {method:"POST", headers:{"Content-Type":"application/json"}});
        const route=`/api/team/${id}`;
        self.__next_f.push([1,/_next/data/b1/raw.json]);
        e.u=function(e){return"static/chunks/app/dashboard-deadbeef.js"};
    "#;
    let expected = comparable(scan_document(body, &base));

    for split in 0..=body.len() {
        let mut scanner = StreamingDocumentScanner::new(base.clone());
        scanner.push(&body[..split]);
        scanner.push(&body[split..]);
        assert_eq!(comparable(scanner.finish()), expected, "split at {split}");
    }
}

#[test]
fn streaming_scan_processes_incremental_prefixes_without_losing_context() {
    let base = Url::parse("https://example.com/_next/static/chunks/app/main.js").unwrap();
    let mut body = Vec::new();
    body.extend_from_slice(&vec![b'a'; 9000]);
    body.extend_from_slice(
        br#"
        const headers={"Content-Type":"application/json"};
        fetch("/api/late", {method:"POST", headers});
        const nested="static/chunks/app/late.js";
    "#,
    );
    body.extend_from_slice(&vec![b'b'; 9000]);
    body.extend_from_slice(br#"const candidate="/api/final/${team}";"#);
    let expected = comparable(scan_document(&body, &base));

    let mut scanner = StreamingDocumentScanner::new(base);
    for chunk in body.chunks(137) {
        scanner.push(chunk);
    }

    assert_eq!(comparable(scanner.finish()), expected);
}

fn scanned(bytes: &[u8]) -> ApiMap {
    let mut apis = ApiMap::default();
    scan(bytes, &mut apis);
    apis
}

fn comparable(result: ScanResult) -> Value {
    let mut refs = result
        .refs
        .iter()
        .map(|url| url.as_str().to_string())
        .collect::<Vec<_>>();
    refs.sort();
    serde_json::json!({
        "apis": result.apis,
        "candidates": result.candidates,
        "routes": result.routes,
        "refs": refs,
    })
}
