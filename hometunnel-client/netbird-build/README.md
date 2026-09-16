# NetBird client dependency overlay

The Dockerfile verifies the NetBird v0.78.2 source archive and builds only `./client` using Go 1.26.8, CGO disabled, and the upstream `load_wgnt_from_rsrc` build tag. The binary identifies as `0.78.2-hometunnel.1`.

The module graph is limited to packages used by the Linux amd64/arm64 client. Unused server, UI and test-only requirements from the upstream root module are excluded. The original source archive is otherwise retained during compilation; `-mod=readonly` prevents undeclared dependency changes.

Security updates include gRPC 1.83.2, Pion DTLS v3.1.4, STUN v3.1.5, GoPacket v1.6.1 and eBPF v0.22.0, plus their required dependencies. `prepare_overlay.py` makes a local copy of checksum-verified STUN v3.1.5 and changes only its client networking imports from transport/v4 to transport/v3, matching NetBird's existing interface implementation. Its security-fixed address parser is unchanged. The local replacement is explicit in go.mod.

To refresh, start with the pinned source, apply the version changes with `go get`, and use `GOOS=linux CGO_ENABLED=0 go list -deps -tags load_wgnt_from_rsrc ./client` for both amd64 and arm64 to retain the modules actually used by the client. Build with `-mod=mod` once when updating the manifest, then check in the resulting go.mod/go.sum and require read-only module resolution for release builds. Verify module hashes, compile both architectures, run STUN tests and the image vulnerability gates. Do not run an unqualified `go mod tidy` against the full upstream tree: it adds unrelated server/UI/test requirements.

Additional updates: golang.org/x/crypto v0.56.0 and klauspost/compress v1.18.7. Legacy STUN v2 receives the same short-address length check as STUN v3.1.5. Legacy DTLS v2 receives the epoch/sequence AES-GCM nonce construction from upstream commit `61762dee8217991882c5eb79856b9e7a73ee349f` (CVE-2026-26014). Both backports use explicit local module replacements with exact source-context checks. Release builds run synthetic short-address and nonce-uniqueness/roundtrip regression tests. These are modified upstream libraries, not unmodified published releases.
