# hifi Architecture

`hifi` maps a web application's visible HTTP surface by scanning the root HTML
document and any static assets that the page references.

## Execution Flow

1. `app` parses CLI arguments into a typed command.
2. `processor` plans the request, checks processed cache, loads the root page,
   scans the root document, recursively scans discovered assets, and builds the
   final output.
3. `discover` finds static assets and framework payloads worth scanning.
4. `scan` extracts API calls, API-like candidates, and client routes from bytes.
5. `fetch` recursively fetches discovered assets with bounded concurrency and a
   hard cap on total assets.
6. `cache` stores best-effort processed results, root pages, asset scans, and
   HTTP validators.
7. `daemon` keeps warm in-memory caches and coalesces concurrent scans for the
   same URL.

## Scanner Shape

The scanner is split by responsibility:

- `scan/patterns.rs`: registers search literals and the kind of evidence each
  literal represents.
- `scan/extract.rs`: extracts URL-like values from quoted strings, object
  values, and raw tokens.
- `scan/classify.rs`: decides whether a value is an API, candidate, route, or
  irrelevant asset.
- `scan/shape.rs`: infers method/body/header/content-type hints for confirmed
  API calls.
- `source.rs`: shared byte-level parsing primitives used by both `scan` and
  `discover`.

The scanner is intentionally heuristic. It is designed to make minified client
bundles understandable without evaluating JavaScript or requiring a full AST.

## Cache Layers

There are three cache layers:

- Processed output cache: final JSON output for a URL.
- Page cache: root page body plus its final redirected URL.
- Asset cache: per-asset scan results, scoped by page revision/cache key.

Cache failures are best-effort. They should not fail a scan; they should only
make future scans colder.

## Network Policy

All network reads should go through `runtime::net`, which centralizes supported
schemes, private-address policy, status handling, and response-size limits.
