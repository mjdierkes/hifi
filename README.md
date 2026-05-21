# hifi

`hifi` maps an HTTP API surface by scanning a web app's HTML and JavaScript chunks.

## Usage

```sh
hifi <url> [--no-cache] [--no-daemon] [--flat|--json]
hifi grep <url> <pattern> [-C N]
hifi serve
```

Examples:

```sh
hifi example.com
hifi https://api.example.com/v2 --json
hifi grep example.com TODO -C 2
```

By default, private and local network addresses are blocked. Set `HIFI_ALLOW_PRIVATE=1` when you intentionally want to scan local services.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

See [`docs/architecture.md`](docs/architecture.md) for the module map and scan lifecycle.

Useful environment variables:

- `HIFI_ALLOW_PRIVATE=1`: allow localhost, private IPs, and `.local` names.
- `HIFI_CHUNK_CONCURRENCY=<n>`: tune concurrent chunk fetches. Values above the hard cap are clamped.
