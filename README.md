# hifi

`hifi` extracts internal APIs by scanning a web app's raw HTML and JavaScript bytes.

## Usage

```sh
hifi <url> [--no-cache] [--json]
hifi grep <url> <pattern> [-C N] [--max-hits N] [--max-bytes-per-hit N] [-a|--all]
```

Examples:

```sh
hifi example.com
hifi https://api.example.com/v2 --json
hifi grep example.com TODO -C 2
```

`hifi grep` prints at most 50 hits by default and truncates each snippet to 200 bytes so noisy bundles stay readable. Use `--max-hits`, `--max-bytes-per-hit`, or `--all` to adjust that.

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
