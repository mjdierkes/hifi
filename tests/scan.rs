use hifi::scan::{scan, scan_candidates, ApiMap, CandidateMap};

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

fn scanned(bytes: &[u8]) -> ApiMap {
    let mut apis = ApiMap::default();
    scan(bytes, &mut apis);
    apis
}
