"""Keep NetBird's transport-v3 interface while using STUN's patched parser.

STUN 3.1.5 moved DialConfig.Net to transport/v4. NetBird 0.78.2 implements
transport/v3, so compile its two client networking imports against v3.
The security-fixed xoraddr parser is untouched. The original module remains
checksum-verified on disk; A local module replacement records this compatibility change.
"""
import pathlib
import subprocess
import shutil
import sys

module_cache = pathlib.Path(subprocess.check_output(["go", "env", "GOMODCACHE"], text=True).strip())
upstream = module_cache / "github.com/pion/stun/v3@v3.1.5"
root = pathlib.Path(sys.argv[1]).resolve()
out = root / "stun"
shutil.copytree(upstream, out, dirs_exist_ok=True)
source = out / "client.go"
text = source.read_text()
for value in ('"github.com/pion/transport/v4"', '"github.com/pion/transport/v4/stdnet"'):
    if text.count(value) != 1:
        raise SystemExit("Unexpected upstream STUN networking imports")
text = text.replace('"github.com/pion/transport/v4"', '"github.com/pion/transport/v3"').replace(
    '"github.com/pion/transport/v4/stdnet"', '"github.com/pion/transport/v3/stdnet"')
source.chmod(0o644)
source.write_text(text)


def patch_module(module, destination, filename, old, new):
    target = root / destination
    shutil.copytree(module_cache / module, target, dirs_exist_ok=True)
    source = target / filename
    value = source.read_text()
    if value.count(old) != 1:
        raise SystemExit("Unexpected upstream security patch context")
    source.chmod(0o644)
    source.write_text(value.replace(old, new))
    target.chmod(0o755)
    for directory in target.rglob("*"):
        if directory.is_dir():
            directory.chmod(0o755)
    return target

# Backport upstream DTLS commit 61762dee8217991882c5eb79856b9e7a73ee349f:
# RFC 9325 requires a unique explicit nonce, constructed from epoch + sequence.
dtls = patch_module("github.com/pion/dtls/v2@v2.2.10", "dtls2",
    "pkg/crypto/ciphersuite/gcm.go",
    '\tif _, err := rand.Read(nonce[4:]); err != nil {\n\t\treturn nil, err\n\t}',
    '\tseq64 := (uint64(pkt.Header.Epoch) << 48) | (pkt.Header.SequenceNumber & 0x0000ffffffffffff)\n\tbinary.BigEndian.PutUint64(nonce[4:], seq64)')
p = dtls / "pkg/crypto/ciphersuite/gcm.go"
p.write_text(p.read_text().replace('\t"crypto/rand"\n', ''))

# Backport STUN 3.1.5's length validation before the first address slice.
stun = patch_module("github.com/pion/stun/v2@v2.0.0", "stun2", "xoraddr.go",
    '\tfamily := bin.Uint16(v[0:2])',
    '\tif len(v) <= 4 {\n\t\treturn io.ErrUnexpectedEOF\n\t}\n\tfamily := bin.Uint16(v[0:2])')
shutil.copyfile(pathlib.Path(__file__).with_name("dtls_security_test.go"), dtls / "pkg/crypto/ciphersuite/hometunnel_security_test.go")
shutil.copyfile(pathlib.Path(__file__).with_name("stun_security_test.go"), stun / "hometunnel_security_test.go")
