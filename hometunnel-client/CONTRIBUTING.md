# Contributing

Contributions are licensed under GPL-3.0-only. Keep secrets and real device data out of patches and fixtures. Use synthetic examples and reserved documentation addresses.

With Python 3.12 in an isolated virtual environment:

```sh
pip install --require-hashes -r rootfs/opt/hometunnel/requirements.txt
python -m unittest discover -s tests
python tests/integration_runtime.py
sh -n rootfs/start.sh
```

The unit suite deliberately stubs optional runtime packages. The separate integration command imports the real installed packages and verifies ingress authorization, minimal proxy diagnostics, upstream selection and Portal log suppression without contacting a live Home Assistant or Portal.

For a dependency update, edit `requirements.in`, regenerate `requirements.txt` using `pip-compile --generate-hashes --strip-extras --no-emit-index-url --no-emit-trusted-host`, then run `pip-audit -r rootfs/opt/hometunnel/requirements.txt` and both suites. Keep package indexes and credentials out of lock files.
