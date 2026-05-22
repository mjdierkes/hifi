# hifi Architecture

`hifi` extracts internal APIs by scanning the root HTML document and any static
assets that the page references.

## Execution Flow

`app` parses commands. `processor` checks `ScanCache`, loads the root page,
scans it, fetches discovered assets, and builds output. `discover` handles
generic HTML/literal/dynamic references; `framework` owns framework-specific
context, asset typing, resolution, payload findings, manifests, and headers.
`fetch` recursively scans assets with bounded concurrency.

## Scanner Shape

The scanner is heuristic: it does not evaluate JavaScript or build an AST.
`source.rs` provides shared byte helpers, `scan/*` turns bytes into evidence,
`FindingsBuilder` is mutable raw evidence, and `ScanResult` is finalized after
route canonicalization, candidate demotion, and compaction.

## Framework Policy

Discovery stays generic. Framework modules own asset classification, resolution,
skip policy, payload/manifest findings, and request headers.

## Cache Layers

Cache failures are best-effort and only make future scans colder. `ScanCache`
owns processed-output paths, TTL policy, and revision lookup. Asset URL and
content-hash caches stay in `runtime::cache`.

## Network Policy

All network reads should go through `runtime::net`, which centralizes supported
schemes, private-address policy, status handling, and response-size limits.
