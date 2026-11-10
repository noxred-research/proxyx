# Third-party notices

ProxyX itself is licensed under [AGPL-3.0-only](LICENSE). This file describes the third-party material that the repository contains or that a build of it links. Their licenses are separate from the ProxyX license and are not changed by it.

This inventory was compiled from the repository tree and each item's own metadata. It is not legal advice.

## Rust dependencies

ProxyX vendors no third-party source code. All Rust dependencies are fetched from crates.io at build time and pinned in [`Cargo.lock`](Cargo.lock); the workspace crates are `publish = false`.

The set of licenses a dependency may carry is enforced in CI by `cargo deny` using [`deny.toml`](deny.toml). The allowed licenses are Apache-2.0 (also with the LLVM exception), MIT, MIT-0, BSD-2-Clause, BSD-3-Clause, ISC, Unicode-3.0, Unicode-DFS-2016, Zlib, MPL-2.0, CC0-1.0, OpenSSL, BSL-1.0 and CDLA-Permissive-2.0. A dependency under any other license fails the build.

To list the licenses of the dependencies of a build, run `cargo deny list` or `cargo metadata`, and keep the license texts that a distribution of a binary requires.

## Native components linked into the binaries

These are built from source by Cargo build scripts and statically linked, so a binary distribution carries their license obligations.

| Component | Crate (version in `Cargo.lock`) | Used by | License |
| --- | --- | --- | --- |
| BoringSSL | `boring-sys` 5.4.0 | `proxyx-intercept` (upstream TLS with browser-grade fingerprints) | OpenSSL and ISC style licenses of BoringSSL; see the `boring-sys` crate for the exact text |
| aws-lc and ring | `aws-lc-sys` 0.47.0, `ring` 0.17.14 | rustls cryptography | ISC, OpenSSL and Apache-2.0 (aws-lc); ring's own license |
| librdkafka | `rdkafka-sys` 4.10.0+2.12.1 | the control plane's Kafka consumer | BSD-2-Clause, with the licenses of its bundled sources in the crate |
| jemalloc | `tikv-jemalloc-sys` 0.6.1 | allocator of both binaries | jemalloc is BSD-2-Clause; the crate is MIT OR Apache-2.0 |

The control plane links the system OpenSSL through librdkafka. That is why it is a separate process from the session proxy, which links BoringSSL.

## Data embedded in the binaries

| Material | Crate (version in `Cargo.lock`) | License |
| --- | --- | --- |
| Mozilla root certificate store (webpki roots) | `webpki-roots` 0.26.11 and 1.0.9 | CDLA-Permissive-2.0 |

`protoc-bin-vendored` 3.3.0 provides the protobuf compiler at build time only; it is not part of a binary.

## Prober (Python)

The optional prober in [`prober/`](prober/) depends on `httpx` (BSD-3-Clause), `pydantic` and `pydantic-settings` (MIT), `prometheus_client` (Apache-2.0) and `playwright` (Apache-2.0). The prober launches a Chromium that you install separately with `playwright install chromium`; the browser build and its licenses are not part of this repository.

## Container images and sidecars

The `docker/` files reference public images (Debian, PostgreSQL, Valkey, ClickHouse, Tailscale) and packages (WireGuard tools, OpenVPN, microsocks). None of them is stored in this repository. Their licenses apply to the images you build or pull.

## Provider names and documentation links

The files in [`data/adapters`](data/adapters) name commercial proxy providers and link to their public documentation, solely to show the adapter format against real username grammars. The names are trademarks of their owners. ProxyX is not affiliated with, endorsed by or sponsored by any of them, and no provider code or content is included.

## Brand assets

The SVG files in [`docs/assets`](docs/assets) are ProxyX project artwork and are covered by the project license.
