use hifi::{scan_endpoints, ScanResult};

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
        let shape = &result.api_map()[url];
        assert_eq!(shape.methods_csv(), methods, "{url}");
        assert_eq!(shape.flags_csv(), flags, "{url}");
    }
}

#[test]
fn api_client_recognizers_cover_common_wrappers() {
    let result = scan(
        r#"
        $fetch("/api/nuxt", { method: "POST", body: payload });
        useFetch("/api/composable?limit=10");
        ky("/api/ky", { method: "PATCH" });
        useRequestFetch()("/api/request-fetch");
        useNuxtApp().$fetch("/api/nuxt-app");
        nuxtApp.$fetch("/api/app-fetch", { method: "POST" });
        this.$api.$get("/api/plugin-get");
        this.$api.$post("/api/plugin-post", payload);
        app.$axios.$delete("/api/axios-delete");
        const API_BASE="/api";
        const playerPath=API_BASE + "/players/player";
        const searchPath=`${API_BASE}/players/search`;
        apiClient.get(playerPath);
        videoService.post(searchPath, payload);
        const gql="/graphql";
        httpClient.post(gql);
        axios({ url: "/api/object", method: "delete" });
        axios({ url: playerPath, method: "put" });
        axios.request({ endpoint: "/graphql", method: "POST", data: body });
    "#,
    );
    for (url, method) in [
        ("/api/nuxt", "POST"),
        ("/api/composable", "GET"),
        ("/api/ky", "PATCH"),
        ("/api/request-fetch", "GET"),
        ("/api/nuxt-app", "GET"),
        ("/api/app-fetch", "POST"),
        ("/api/plugin-get", "GET"),
        ("/api/plugin-post", "POST"),
        ("/api/axios-delete", "DELETE"),
        ("/api/players/player", "GET,PUT"),
        ("/api/players/search", "POST"),
        ("/api/object", "DELETE"),
        ("/graphql", "POST"),
    ] {
        let shape = &result.api_map()[url];
        assert_eq!(shape.methods_csv(), method, "{url}");
    }
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
    for url in [
        "/api/users",
        "/graphql",
        "https://x.test/api/team",
        "/api/raw",
    ] {
        assert_candidate(&result, url);
    }
    assert!(!result.candidate_map().contains_key("/api/users/"));
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
        assert_route(&result, url);
    }
    assert_candidate(&result, "/api/team/{dynamic}");
    assert_no_route(&result, "/api/users");
    assert_no_route(&result, "/images/logo.png");
}

#[test]
fn rejects_non_endpoint_noise() {
    let result = scan(
        r#"
        map.get("session_id");
        fetch("/images/LOGO.PNG?cache=1");
        fetch("/api/users");
        fetch(`${base}/api/admin`);
        const onlyDynamic = `/${id}`;
        const wasm = "/assets/rnnoise.wasm";
        fetch(wasm);
        let svg = "%3Csvg xmlns='http://www.w3.org/2000/svg' %3E%3Cfilter id='b'%3E%3CfeGaussianBlur stdDeviation='20'/%3E%3C/filter%3E%3C/svg%3E";
        router.push("/dashboard");
    "#,
    );

    assert_eq!(result.api_map().len(), 1);
    assert_api(&result, "/api/users");
    assert_route(&result, "/dashboard");
    for url in ["/api/admin", "{dynamic}/api/admin", "/assets/rnnoise.wasm"] {
        assert_no_api(&result, url);
    }
    let url = "/{dynamic}";
    assert_no_api(&result, url);
    assert!(!result.candidate_map().contains_key(url));
    assert_no_route(&result, url);
    for route in [
        "/%3E%3CfeGaussianBlur",
        "/%3E%3C/filter%3E",
        "/%3E%3C/svg%3E",
    ] {
        assert_no_route(&result, route);
    }
}

#[test]
fn rejects_real_world_route_noise_without_dropping_routes() {
    let result = scan(
        r#"
        const routes=["/docs/kit/load","/blog/runes","/themes/details/starlight","/products/bolts"];
        const source="/assets/app/assets/entry.ts";
        const files=["/src/app.html","/src/lib","/node_modules","/.env","/.git","/vercel/path0"];
        const runtime=["/dev/null","/proc/self/fd","/home/web_user","/opfs","/tmp"];
        const random=["/ZQ!fOG27VO4UQ!fOG27VO","/UO!_$cX$Z$cX$","/0LN\\\\\\\\_abefnprtv"];
        const generated=["/*@__PURE__*","/:ids+.","/rmx:h","/dev/null/inferredProject/foo"];
        const api="/api/users";
    "#,
    );
    for route in [
        "/docs/kit/load",
        "/blog/runes",
        "/themes/details/starlight",
        "/products/bolts",
    ] {
        assert_route(&result, route);
    }
    for route in [
        "/assets/app/assets/entry.ts",
        "/src/app.html",
        "/src/lib",
        "/node_modules",
        "/.env",
        "/.git",
        "/vercel/path0",
        "/dev/null",
        "/proc/self/fd",
        "/home/web_user",
        "/opfs",
        "/tmp",
        "/ZQ!fOG27VO4UQ!fOG27VO",
        "/UO!_$cX$Z$cX$",
        "/0LN\\\\\\\\_abefnprtv",
        "/*@__PURE__*",
        "/:ids+.",
        "/rmx:h",
        "/dev/null/inferredProject/foo",
    ] {
        assert_no_route(&result, route);
    }
    assert_candidate(&result, "/api/users");
}

fn scan(src: &str) -> ScanResult {
    scan_endpoints(src.as_bytes()).finish()
}

fn assert_api(result: &ScanResult, url: &str) {
    assert!(result.api_map().contains_key(url), "{url}");
}

fn assert_no_api(result: &ScanResult, url: &str) {
    assert!(!result.api_map().contains_key(url), "{url}");
}

fn assert_candidate(result: &ScanResult, url: &str) {
    assert!(result.candidate_map().contains_key(url), "{url}");
}

fn assert_route(result: &ScanResult, url: &str) {
    assert!(result.route_map().contains_key(url), "{url}");
}

fn assert_no_route(result: &ScanResult, url: &str) {
    assert!(!result.route_map().contains_key(url), "{url}");
}
