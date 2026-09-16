# Licensing and third-party components

HomeTunnel Client source in this release is distributed under GNU GPL version 3 only (`GPL-3.0-only`); see `LICENSE`. No warranty is provided.
The prior distribution's Apache-2.0 license text is retained in `LICENSES/Apache-2.0-prior-distribution.txt` for provenance.

NetBird client 0.78.2 is downloaded separately during the image build. Its BSD-3-Clause notice is retained in `LICENSES/NetBird-BSD-3-Clause.txt`. The NetBird server components mentioned in that notice are not bundled by this add-on. NetBird source for this binary: https://github.com/netbirdio/netbird/tree/v0.78.2.

The container also contains the Home Assistant community base image, Alpine packages, and Python dependencies under their respective licenses. Installed Python package metadata and OS package metadata retain their notices. This project's GPL license does not replace third-party licenses. Build sources and instructions are provided in `Dockerfile`, `build.yaml`, and the Python dependency input/lock files.
