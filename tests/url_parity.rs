use hifi::url::{Host, Url};

const URLS: &[&str] = &[
    "https://example.com/",
    "HTTPS://Example.COM",
    "http://example.com:80/a/b?x=1#frag",
    "https://example.com:443/a/b?x=1#frag",
    "https://example.com:8443/a/b?x=1#frag",
    "https://user:pass@example.com/a/b?x=1",
    "http://127.0.0.1:3000/latest",
    "http://169.254.169.254/latest",
    "http://[::1]:8080/path?q=a+b",
    "https://example.com/_next/static/chunks/app.js",
    "https://example.com/app/_payload.json?x=%7B1%7D",
    "https://example.com/path;param/file.js?empty=&flag",
    "https://example.com/a%20b/c%7Bd%7D?x=%2Fapi%2Fv1",
    "https://cdn.example.com/assets/../static/app.js",
    "https://example.com/base/page.html?_data=routes%2Findex",
    "https://例え.テスト/パス?q=é#フラグ",
    "https://example.com/café?q=mañana",
];

const RELATIVES: &[&str] = &[
    "",
    "#fragment",
    "?query=1",
    "child.js",
    "./child.js",
    "../sibling.css",
    "/rooted/data.json",
    "//cdn.example.com/lib.js",
    "https://other.example.com/final",
];

#[test]
fn matches_upstream_url_surface_for_real_urls() {
    for raw in URLS {
        let ours = Url::parse(raw).unwrap_or_else(|err| panic!("ours failed {raw}: {err}"));
        let upstream =
            url_crate::Url::parse(raw).unwrap_or_else(|err| panic!("upstream failed {raw}: {err}"));
        assert_url_snapshot(raw, &ours, &upstream);
    }
}

#[test]
fn matches_upstream_join_surface_for_real_urls() {
    for base in URLS {
        let ours = Url::parse(base).unwrap();
        let upstream = url_crate::Url::parse(base).unwrap();
        for relative in RELATIVES {
            let ours_joined = ours
                .join(relative)
                .unwrap_or_else(|err| panic!("ours failed {base} + {relative}: {err}"));
            let upstream_joined = upstream
                .join(relative)
                .unwrap_or_else(|err| panic!("upstream failed {base} + {relative}: {err}"));
            assert_url_snapshot(
                &format!("{base} + {relative}"),
                &ours_joined,
                &upstream_joined,
            );
        }
    }
}

#[test]
fn matches_upstream_setter_surface() {
    let mut ours = Url::parse("https://example.com/a/b?x=1#frag").unwrap();
    let mut upstream = url_crate::Url::parse("https://example.com/a/b?x=1#frag").unwrap();
    ours.set_path("/next/file.js");
    upstream.set_path("/next/file.js");
    ours.set_query(Some("a=b+c&x=%7B1%7D"));
    upstream.set_query(Some("a=b+c&x=%7B1%7D"));
    ours.set_fragment(None);
    upstream.set_fragment(None);
    assert_url_snapshot("setters", &ours, &upstream);
}

#[test]
fn fuzz_ascii_parse_and_join_parity_matrix() {
    let schemes = ["http", "https", "HTTP", "HTTPS"];
    let hosts = [
        "example.com",
        "EXAMPLE.com",
        "sub.example.com",
        "127.0.0.1",
        "[::1]",
    ];
    let ports = ["", ":80", ":443", ":3000", ":65535"];
    let paths = [
        "",
        "/",
        "/a",
        "/a/b",
        "/a/./b",
        "/a/b/../c",
        "/_next/static/app.js",
        "/path%20with%20space/file.js",
    ];
    let queries = ["", "?x=1", "?a=b+c", "?encoded=%7Bvalue%7D", "?flag&empty="];
    let fragments = ["", "#top", "#hash%20value"];
    let relatives = [
        "",
        ".",
        "./next.js",
        "../up.css",
        "/root.json",
        "?q=2",
        "#frag",
        "//cdn.example.com/a.js",
    ];

    let mut checked = 0usize;
    for scheme in schemes {
        for host in hosts {
            for port in ports {
                for path in paths {
                    for query in queries {
                        for fragment in fragments {
                            let raw = format!("{scheme}://{host}{port}{path}{query}{fragment}");
                            let ours = Url::parse(&raw);
                            let upstream = url_crate::Url::parse(&raw);
                            assert_eq!(
                                ours.is_ok(),
                                upstream.is_ok(),
                                "parse success diverged for {raw}: ours={ours:?} upstream={upstream:?}"
                            );
                            let (Ok(ours), Ok(upstream)) = (ours, upstream) else {
                                continue;
                            };
                            assert_url_snapshot(&raw, &ours, &upstream);
                            for relative in relatives {
                                let ours_joined = ours.join(relative);
                                let upstream_joined = upstream.join(relative);
                                assert_eq!(
                                    ours_joined.is_ok(),
                                    upstream_joined.is_ok(),
                                    "join success diverged for {raw} + {relative}: ours={ours_joined:?} upstream={upstream_joined:?}"
                                );
                                let (Ok(ours_joined), Ok(upstream_joined)) =
                                    (ours_joined, upstream_joined)
                                else {
                                    continue;
                                };
                                assert_url_snapshot(
                                    &format!("{raw} + {relative}"),
                                    &ours_joined,
                                    &upstream_joined,
                                );
                                checked += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(checked > 10_000);
}

fn assert_url_snapshot(label: &str, ours: &Url, upstream: &url_crate::Url) {
    assert_eq!(ours.as_str(), upstream.as_str(), "{label}: as_str");
    assert_eq!(ours.to_string(), upstream.to_string(), "{label}: Display");
    assert_eq!(ours.scheme(), upstream.scheme(), "{label}: scheme");
    assert_eq!(ours.host_str(), upstream.host_str(), "{label}: host_str");
    assert_eq!(ours.port(), upstream.port(), "{label}: port");
    assert_eq!(
        ours.port_or_known_default(),
        upstream.port_or_known_default(),
        "{label}: port_or_known_default"
    );
    assert_eq!(ours.path(), upstream.path(), "{label}: path");
    assert_eq!(ours.query(), upstream.query(), "{label}: query");
    assert_eq!(ours.fragment(), upstream.fragment(), "{label}: fragment");
    assert_eq!(
        host_snapshot(ours.host()),
        upstream.host().map(|host| format!("{host:?}")),
        "{label}: host"
    );
    assert_eq!(
        ours.query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<Vec<_>>(),
        upstream
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<Vec<_>>(),
        "{label}: query_pairs"
    );
}

fn host_snapshot(host: Option<Host<'_>>) -> Option<String> {
    host.map(|host| match host {
        Host::Domain(domain) => format!("Domain({domain:?})"),
        Host::Ipv4(ip) => format!("Ipv4({ip:?})"),
        Host::Ipv6(ip) => format!("Ipv6({ip:?})"),
    })
}
