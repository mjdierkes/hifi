use crate::scan::{self, html};
use crate::scan::{ApiMap, CandidateMap};

use super::{cache, fetch};
use reqwest::Client;
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::Instant,
};
use url::Url;

pub const CACHE_FRESH_SECS: u64 = 300;
pub const CACHE_STALE_SECS: u64 = 3600;
const MEMORY_CACHE_MAX_ENTRIES: usize = 256;

type Result<T, E = Box<dyn Error>> = std::result::Result<T, E>;
pub type Body = Arc<str>;
pub type MemoryCache = Arc<RwLock<FxHashMap<String, (Body, Instant)>>>;
pub type RedirectMemory = Arc<RwLock<FxHashMap<String, Url>>>;

#[derive(Clone, Serialize, Deserialize)]
pub struct Output {
    pub apis: ApiMap,
    #[serde(default, skip_serializing_if = "CandidateMap::is_empty")]
    pub candidates: CandidateMap,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_id: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cache: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_age_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_us: Option<u128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timings: Option<TimingStats>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats: Option<RunStats>,
}

impl Output {
    pub fn to_json_string(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    fn mark(mut self, t0: Option<Instant>, cache: &str, age_secs: Option<u64>) -> Self {
        self.cache.clear();
        self.cache.push_str(cache);
        self.cache_age_secs = age_secs;
        self.elapsed_us = t0.map(|t| t.elapsed().as_micros());
        self
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct TimingStats {
    pub page_fetch_us: u128,
    pub html_scan_us: u128,
    pub manifest_fetch_us: u128,
    pub manifest_scan_us: u128,
    pub chunk_wall_us: u128,
    pub chunk_fetch_us: u128,
    pub chunk_scan_us: u128,
    pub chunk_ref_us: u128,
    pub chunk_api_scan_us: u128,
    pub chunk_candidate_scan_us: u128,
    pub total_us: u128,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct RunStats {
    pub html_bytes: u64,
    pub page_cache_hit: bool,
    pub page_bytes_fetched: u64,
    pub manifest_bytes: u64,
    pub chunk_bytes_fetched: u64,
    pub chunk_bytes_scanned: u64,
    pub chunks_discovered: usize,
    pub chunks_scanned: usize,
    pub chunk_cache_hits: usize,
    pub chunk_bundle_hits: usize,
    pub chunk_bundle_pack_hits: usize,
    pub chunk_memory_hits: usize,
    pub manifest_scanned: usize,
    pub manifest_errors: usize,
    pub chunk_errors: usize,
    pub scan_mib_per_sec: f64,
    pub fetch_mib_per_sec: f64,
}

impl RunStats {
    fn from_parts(
        html_bytes: u64,
        page_cache_hit: bool,
        manifest: &ManifestStats,
        chunks: &fetch::ChunkScanStats,
        timings: &TimingStats,
    ) -> Self {
        let scanned_bytes = html_bytes + manifest.bytes + chunks.bytes_scanned;
        let page_bytes_fetched = if page_cache_hit { 0 } else { html_bytes };
        let fetched_bytes = page_bytes_fetched + manifest.bytes + chunks.bytes_fetched;
        let scan_us = timings.html_scan_us + timings.manifest_scan_us + timings.chunk_scan_us;
        let fetch_us = timings.page_fetch_us + timings.manifest_fetch_us + timings.chunk_wall_us;
        Self {
            html_bytes,
            page_cache_hit,
            page_bytes_fetched,
            manifest_bytes: manifest.bytes,
            chunk_bytes_fetched: chunks.bytes_fetched,
            chunk_bytes_scanned: chunks.bytes_scanned,
            chunks_discovered: chunks.discovered,
            chunks_scanned: chunks.scanned,
            chunk_cache_hits: chunks.cache_hits,
            chunk_bundle_hits: chunks.bundle_hits,
            chunk_bundle_pack_hits: chunks.bundle_pack_hits,
            chunk_memory_hits: chunks.memory_hits,
            manifest_scanned: manifest.scanned,
            manifest_errors: manifest.errors,
            chunk_errors: chunks.errors,
            scan_mib_per_sec: mib_per_sec_from_us(scanned_bytes, scan_us),
            fetch_mib_per_sec: mib_per_sec_from_us(fetched_bytes, fetch_us),
        }
    }
}

fn mib_per_sec_from_us(bytes: u64, us: u128) -> f64 {
    if bytes == 0 || us == 0 {
        return 0.0;
    }
    (bytes as f64 / 1_048_576.0) / (us as f64 / 1_000_000.0)
}

#[derive(Clone, Default)]
pub struct CacheContext {
    pub memory: Option<MemoryCache>,
    pub chunks: Option<fetch::ChunkMemoryCache>,
    pub redirects: Option<RedirectMemory>,
}

pub struct Processor<'a> {
    client: &'a Client,
    concurrency: usize,
    cache: CacheContext,
}

impl<'a> Processor<'a> {
    pub fn new(client: &'a Client, concurrency: usize, cache: CacheContext) -> Self {
        Self {
            client,
            concurrency,
            cache,
        }
    }

    pub async fn process(&self, url: &str, no_cache: bool, t0: Instant) -> Result<String> {
        self.process_for_display(url, no_cache, t0)
            .await?
            .to_json_string()
    }

    pub async fn process_for_display(
        &self,
        url: &str,
        no_cache: bool,
        t0: Instant,
    ) -> Result<Output> {
        self.process_typed(url, no_cache, Some(t0)).await
    }

    async fn process_typed(
        &self,
        url: &str,
        no_cache: bool,
        t0: Option<Instant>,
    ) -> Result<Output> {
        let active_cache = if no_cache {
            CacheContext::default()
        } else {
            self.cache.clone()
        };
        let (base, cache_path, request_base) = request_parts(url, &active_cache)?;

        if let Some((json, age)) = (!no_cache)
            .then(|| cache::read_any_bytes(&cache_path))
            .flatten()
            .filter(|(_, age)| *age < CACHE_STALE_SECS)
        {
            let status = if age < CACHE_FRESH_SECS {
                "fresh"
            } else {
                self.refresh_later(url, active_cache.clone());
                "stale"
            };
            let t0 = t0.unwrap_or_else(Instant::now);
            return Ok(serde_json::from_slice::<Output>(&json)?.mark(Some(t0), status, Some(age)));
        }

        let (out, cache_hit) = self
            .collect(
                url,
                &base,
                &request_base,
                (!no_cache).then_some(cache_path.as_path()),
                t0,
                active_cache,
            )
            .await?;

        if !no_cache && !cache_hit {
            write_caches(&cache_path, &out, url, self.cache.memory.clone())?;
        }
        Ok(out)
    }

    pub async fn refresh(&self, url: &str) -> Result<()> {
        let (base, cache_path, request_base) = request_parts(url, &self.cache)?;
        let (out, _) = self
            .collect(
                url,
                &base,
                &request_base,
                Some(cache_path.as_path()),
                None,
                self.cache.clone(),
            )
            .await?;
        write_caches(&cache_path, &out, url, self.cache.memory.clone())
    }

    fn refresh_later(&self, url: &str, cache: CacheContext) {
        spawn_refresh(self.client.clone(), self.concurrency, url, cache);
    }

    async fn collect(
        &self,
        _url: &str,
        original_base: &Url,
        request_base: &Url,
        cache_path: Option<&Path>,
        t0: Option<Instant>,
        cache_ctx: CacheContext,
    ) -> Result<(Output, bool)> {
        let (html, final_base, page_fetch_us, page_cache_hit) = if let Some((body, final_base)) =
            cache_path
                .is_none()
                .then(|| cache::read_page(request_base))
                .flatten()
        {
            (bytes::Bytes::from(body), final_base, 0, true)
        } else {
            let page_fetch_t0 = Instant::now();
            let response = self.client.get(request_base.clone()).send().await?;
            let final_base = response.url().clone();
            remember_redirect(cache_ctx.redirects.as_ref(), original_base, &final_base);
            let html = response.bytes().await?;
            let page_fetch_elapsed = page_fetch_t0.elapsed();
            cache::write_page(request_base, &final_base, &html);
            (html, final_base, page_fetch_elapsed.as_micros(), false)
        };
        let html_bytes = html.len() as u64;
        let html_scan_t0 = Instant::now();
        let mut chunks = html::extract_chunks(&html, &final_base);
        let html_build_id = html::extract_build_id(&html);
        let build_id = html_build_id
            .clone()
            .or_else(|| Some(cache::fingerprint(&chunks)));
        let html_parse_elapsed = html_scan_t0.elapsed();

        if let Some(path) = cache_path {
            if let (Some(bytes), Some(t0)) =
                (cache::read_build_bytes(path, build_id.as_deref()), t0)
            {
                return Ok((
                    serde_json::from_slice::<Output>(&bytes)?.mark(Some(t0), "hit", None),
                    true,
                ));
            }
        }

        let html_scan_body = html.clone();
        let html_scan_task = tokio::task::spawn_blocking(move || {
            let mut apis = ApiMap::default();
            let mut candidates = CandidateMap::default();
            let html_scan_t0 = Instant::now();
            scan::scan(&html_scan_body, &mut apis);
            scan::scan_candidates(&html_scan_body, &mut candidates);
            (apis, candidates, html_scan_t0.elapsed())
        });
        let mut manifest_apis = ApiMap::default();
        let mut manifest_candidates = CandidateMap::default();
        let manifest_stats = scan_next_manifests(
            self.client,
            &final_base,
            html_build_id.as_deref(),
            &mut manifest_apis,
            &mut manifest_candidates,
            &mut chunks,
        )
        .await;
        let chunk_wall_t0 = Instant::now();
        let mut apis = ApiMap::default();
        let mut candidates = CandidateMap::default();
        let chunk_stats = fetch::scan_chunks(
            self.client.clone(),
            chunks.iter().cloned(),
            fetch::ChunkScanOptions {
                concurrency: self.concurrency,
                use_processed_cache: cache_path.is_some(),
                use_bundle_cache: true,
                memory: cache_ctx.chunks,
            },
            &mut apis,
            &mut candidates,
        )
        .await;
        let chunk_wall_elapsed = chunk_wall_t0.elapsed();
        let (html_apis, html_candidates, html_scan_elapsed) = html_scan_task.await?;
        scan::merge_into(&mut apis, html_apis);
        scan::merge_candidates_into(&mut candidates, html_candidates);
        scan::merge_into(&mut apis, manifest_apis);
        scan::merge_candidates_into(&mut candidates, manifest_candidates);
        let html_scan_us = html_parse_elapsed.as_micros() + html_scan_elapsed.as_micros();
        for url in apis.keys() {
            candidates.remove(url);
        }

        let total_elapsed = t0.map(|t| t.elapsed());
        let total_us = total_elapsed.map(|e| e.as_micros()).unwrap_or(0);
        let timings = TimingStats {
            page_fetch_us,
            html_scan_us,
            manifest_fetch_us: manifest_stats.fetch_us,
            manifest_scan_us: manifest_stats.scan_us,
            chunk_wall_us: chunk_wall_elapsed.as_micros(),
            chunk_fetch_us: chunk_stats.fetch_us,
            chunk_scan_us: chunk_stats.scan_us,
            chunk_ref_us: chunk_stats.ref_us,
            chunk_api_scan_us: chunk_stats.api_scan_us,
            chunk_candidate_scan_us: chunk_stats.candidate_scan_us,
            total_us,
        };
        let stats = RunStats::from_parts(
            html_bytes,
            page_cache_hit,
            &manifest_stats,
            &chunk_stats,
            &timings,
        );
        Ok((
            Output {
                apis,
                candidates,
                build_id,
                cache: "miss".into(),
                cache_age_secs: None,
                elapsed_us: t0.map(|_| total_us),
                timings: Some(timings),
                stats: Some(stats),
            },
            false,
        ))
    }
}

pub fn spawn_refresh(client: Client, concurrency: usize, url: &str, cache: CacheContext) {
    let url = url.to_string();
    tokio::spawn(async move {
        let _ = Processor::new(&client, concurrency, cache)
            .refresh(&url)
            .await;
    });
}

pub fn read_memory(memory: &MemoryCache, url: &str) -> Option<(Body, u64)> {
    memory
        .read()
        .ok()?
        .get(url)
        .cloned()
        .map(|(body, t)| (body, t.elapsed().as_secs()))
}

pub fn write_memory(memory: &MemoryCache, url: String, body: Body) {
    if let Ok(mut entries) = memory.write() {
        let now = Instant::now();
        entries.insert(url, (body, now));
        prune_memory(&mut entries, now);
    }
}

#[derive(Default)]
struct ManifestStats {
    scanned: usize,
    errors: usize,
    bytes: u64,
    fetch_us: u128,
    scan_us: u128,
}

async fn scan_next_manifests(
    client: &Client,
    base: &Url,
    build_id: Option<&str>,
    apis: &mut ApiMap,
    candidates: &mut CandidateMap,
    chunks: &mut Vec<Url>,
) -> ManifestStats {
    let Some(build_id) = build_id else {
        return ManifestStats::default();
    };

    let mut stats = ManifestStats::default();
    for name in ["_buildManifest.js", "_ssgManifest.js"] {
        let Ok(manifest_url) = base.join(&format!("/_next/static/{build_id}/{name}")) else {
            continue;
        };
        match fetch_manifest(client, manifest_url.clone()).await {
            Some((body, fetch_elapsed)) => {
                stats.scanned += 1;
                stats.fetch_us += fetch_elapsed.as_micros();
                stats.bytes += body.len() as u64;
                let scan_t0 = Instant::now();
                scan::scan(&body, apis);
                scan::scan_candidates(&body, candidates);
                chunks.extend(html::extract_chunk_refs(&body, &manifest_url));
                let scan_elapsed = scan_t0.elapsed();
                stats.scan_us += scan_elapsed.as_micros();
            }
            None => stats.errors += 1,
        }
    }
    stats
}

async fn fetch_manifest(client: &Client, url: Url) -> Option<(bytes::Bytes, std::time::Duration)> {
    let t0 = Instant::now();
    let bytes = client
        .get(url)
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .bytes()
        .await
        .ok()?;
    Some((bytes, t0.elapsed()))
}

fn redirected_base(redirects: Option<&RedirectMemory>, base: &Url) -> Option<Url> {
    let target = redirects?.read().ok()?.get(&origin_key(base)?).cloned()?;
    let mut out = target;
    out.set_path(base.path());
    out.set_query(base.query());
    out.set_fragment(base.fragment());
    Some(out)
}

fn request_parts(url: &str, cache: &CacheContext) -> Result<(Url, PathBuf, Url), url::ParseError> {
    let base = Url::parse(url)?;
    let request_base =
        redirected_base(cache.redirects.as_ref(), &base).unwrap_or_else(|| base.clone());
    let cache_path = cache::path_for(&base);
    Ok((base, cache_path, request_base))
}

fn remember_redirect(redirects: Option<&RedirectMemory>, from: &Url, to: &Url) {
    let (Some(from_key), Some(to_key)) = (origin_key(from), origin_key(to)) else {
        return;
    };
    if from_key == to_key {
        return;
    }
    if let Some(redirects) = redirects {
        if let Ok(mut entries) = redirects.write() {
            if let Ok(to_origin) = Url::parse(&format!("{to_key}/")) {
                entries.insert(from_key, to_origin);
            }
        }
    }
}

fn origin_key(url: &Url) -> Option<String> {
    let host = url.host_str()?;
    match url.port() {
        Some(port) => Some(format!("{}://{}:{}", url.scheme(), host, port)),
        None => Some(format!("{}://{}", url.scheme(), host)),
    }
}

fn write_caches(
    cache_path: &Path,
    out: &Output,
    url: &str,
    memory: Option<MemoryCache>,
) -> Result<()> {
    let cached = out.clone().mark(None, "", None);
    cache::write_with_build_id(cache_path, &cached, out.build_id.as_deref());
    if let Some(memory) = memory {
        let body = Arc::from(out.to_json_string()?);
        write_memory(&memory, url.to_string(), body);
    }
    Ok(())
}

fn prune_memory(entries: &mut FxHashMap<String, (Body, Instant)>, now: Instant) {
    entries.retain(|_, (_, written)| {
        now.saturating_duration_since(*written).as_secs() < CACHE_STALE_SECS
    });
    cache::prune_overflow(entries, MEMORY_CACHE_MAX_ENTRIES);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn cache_value_strips_dynamic_fields() {
        let cached = Output {
            apis: ApiMap::default(),
            candidates: CandidateMap::default(),
            build_id: Some("b1".into()),
            cache: "miss".into(),
            cache_age_secs: Some(1),
            elapsed_us: Some(1000),
            timings: Some(TimingStats::default()),
            stats: Some(RunStats::default()),
        }
        .mark(None, "", None);
        let v = serde_json::to_value(&cached).unwrap();
        assert!(v.get("apis").is_some());
        assert!(v.get("build_id").is_some());
        assert!(v.get("cache_age_secs").is_none());
        assert!(v.get("elapsed_us").is_none());
    }

    #[tokio::test]
    async fn build_manifest_seeds_extra_chunks() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            for _ in 0..4 {
                let (mut socket, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = [0; 2048];
                    let n = socket.read(&mut buf).await.unwrap();
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let (status, body) = if req
                        .starts_with("GET /_next/static/b1/_buildManifest.js ")
                    {
                        (
                            "200 OK",
                            r#"self.__BUILD_MANIFEST={"/extra":["static/chunks/app-extra.js"]};const u="/api/from-manifest";"#,
                        )
                    } else if req.starts_with("GET /_next/static/chunks/app-extra.js ") {
                        ("200 OK", r#"fetch("/api/from-chunk",{method:"POST"})"#)
                    } else if req.starts_with("GET /_next/static/b1/_ssgManifest.js ") {
                        ("404 Not Found", "")
                    } else {
                        (
                            "200 OK",
                            r#"<html><script id="__NEXT_DATA__" type="application/json">{"buildId":"b1"}</script></html>"#,
                        )
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    socket.write_all(response.as_bytes()).await.unwrap();
                });
            }
        });

        let client = Client::new();
        let out = Processor::new(&client, 2, CacheContext::default())
            .process(&format!("http://{addr}/"), true, Instant::now())
            .await
            .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();

        assert!(v["apis"].get("/api/from-chunk").is_some());
        assert!(v["candidates"].get("/api/from-manifest").is_some());
    }
}
