[![CI](https://github.com/infrasonar/tcp-probe/workflows/CI/badge.svg)](https://github.com/infrasonar/tcp-probe/actions)
[![Release Version](https://img.shields.io/github/release/infrasonar/tcp-probe)](https://github.com/infrasonar/tcp-probe/releases)

# InfraSonar Tcp Probe

## Docker build

```
docker build -t tcp-probe . --no-cache
```

## Dry run

Available checks:
- `certificates`
- `ports`

Create a yaml file, for example _(test.yaml)_:

```yaml
asset:
  name: "foo.local"
  check: "certificates"
  config:
    address: "192.168.1.2"
    checkCertificatePorts: [443]  # not required, defaults to [443, 995, 993, 465, 3389, 989, 990, 636, 5986] when this option is emitted
```

Run the probe with the `DRY_RUN` environment variable set the the yaml file above.

Or for the ports check:

```yaml
asset:
  name: "foo.local"
  check: "ports"
  config:
    address: "192.168.1.2"
    checkCertificatePorts: [80, 1433]
```

```
DRY_RUN=test.yaml python main.py
```
