[![CI](https://github.com/infrasonar/tcp-probe/workflows/CI/badge.svg)](https://github.com/infrasonar/tcp-probe/actions)
[![Release Version](https://img.shields.io/github/release/infrasonar/tcp-probe)](https://github.com/infrasonar/tcp-probe/releases)

# InfraSonar Tcp Probe

## Environment variable

Variable            | Default                        | Description
------------------- | ------------------------------ | ------------
`AGENTCORE_HOST`    | `127.0.0.1`                    | Hostname or Ip address of the AgentCore.
`AGENTCORE_PORT`    | `8750`                         | AgentCore port to connect to.
`INFRASONAR_CONF`   | `/data/config/infrasonar.yaml` | File with probe and asset configuration like credentials.
`MAX_PACKAGE_SIZE`  | `500`                          | Maximum package size in kilobytes _(1..2000)_.
`MAX_CHECK_TIMEOUT` | `300`                          | Check time-out is 80% of the interval time with `MAX_CHECK_TIMEOUT` in seconds as absolute maximum.
`DRY_RUN`           | _none_                         | Do not run demonized, just return checks and assets specified in the given yaml _(see the [Dry run section](#dry-run) below)_.
`LOG_LEVEL`         | `warning`                      | Log level (`debug`, `info`, `warning`, `error` or `critical`).
`LOG_COLORIZED`     | `0`                            | Log using colors (`0`=disabled, `1`=enabled).
`LOG_FMT`           | `%y%m%d %H:%M:%S`              | Log format prefix.

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
