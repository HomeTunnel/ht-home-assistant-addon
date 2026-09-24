# Licensing and third-party components

HomeTunnel Client source in this release is distributed under GNU GPL version 3 only (`GPL-3.0-only`); see `LICENSE`. No warranty is provided.
The prior distribution's Apache-2.0 license text is retained in `LICENSES/Apache-2.0-prior-distribution.txt` for provenance.

NetBird client 0.78.2 is built from checksum-verified upstream source with Go 1.26.8 and gRPC 1.83.2 and patched network-parser dependencies. This modified build identifies itself as `0.78.2-hometunnel.1`; the exact dependency changes are recorded in `netbird-build/go.mod` and `go.sum`; `prepare_overlay.py` adapts STUN 3.1.5’s networking interface to NetBird’s transport-v3 interface while retaining the fixed parser. Its BSD-3-Clause notice is retained in `LICENSES/NetBird-BSD-3-Clause.txt`. The separate NetBird server executables are not built by this add-on. The upstream directory-specific AGPL-3.0 notice is also retained; those upstream license terms remain applicable. Upstream source: https://github.com/netbirdio/netbird/tree/v0.78.2.

The build also retains available license/notice files for compiled Go modules under `/usr/share/licenses/hometunnel/netbird-dependencies/`, with a module/version manifest.

The container also contains the Home Assistant community base image, Alpine packages, and Python dependencies under their respective licenses. Installed Python package metadata and OS package metadata retain their notices. This project's GPL license does not replace third-party licenses. Build sources and instructions are provided in `Dockerfile`, `build.yaml`, and the Python dependency input/lock files.
