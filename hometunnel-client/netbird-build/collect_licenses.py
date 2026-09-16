"""Retain license/notice files for the Go modules compiled into the client."""
import json
import pathlib
import re
import shutil
import subprocess
import sys

raw = subprocess.check_output(["go", "list", "-deps", "-json", "-tags", "load_wgnt_from_rsrc", "./client"], text=True)
decoder = json.JSONDecoder()
modules = {}
while raw.strip():
    raw = raw.lstrip()
    package, end = decoder.raw_decode(raw)
    raw = raw[end:]
    module = package.get("Module")
    if module and not module.get("Main"):
        modules[module["Path"]] = module
out = pathlib.Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)
manifest = []
for name, module in sorted(modules.items()):
    selected = module.get("Replace") or module
    root = pathlib.Path(selected["Dir"])
    dest = out / re.sub(r"[^A-Za-z0-9._-]", "_", name)
    dest.mkdir(exist_ok=True)
    found = []
    for item in sorted(root.iterdir()):
        if item.is_file() and re.match(r"(?i)^(licen[cs]e|copying|copyright|notice)([._-].*)?$", item.name):
            shutil.copyfile(item, dest / item.name)
            found.append(item.name)
    manifest.append({"module": name, "version": module.get("Version"), "notices": found})
    if not found:
        print("License notice needs upstream lookup:", name)
(out / "modules.json").write_text(json.dumps(manifest, indent=2) + "\n")
