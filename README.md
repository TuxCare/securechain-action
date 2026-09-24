# SecureChain GitHub Action

Runs the [SecureChain CLI](https://securechain.tuxcare.com) gate against your
repository and uploads its findings to GitHub code scanning.

This repository holds no CLI source. The action downloads the released binary
for a **pinned** version through the same install script every customer uses,
verifies its checksum against the release's `checksums.txt` before anything
runs, then runs `securechain check`. The default version is the release this
action was published with: `v0.1.8`.

## Usage

```yaml
on: [push, pull_request]
permissions:
  contents: read
  security-events: write   # for the SARIF upload
jobs:
  securechain:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 22 }
      - run: npm ci
      - uses: TuxCare/securechain-action@v0
        env:
          TUXCARE_TOKEN: ${{ secrets.TUXCARE_TOKEN }}
```

`@v0` follows the newest release of the 0.x line; `@v0.1.8` pins one
release of the action, which pins one release of the CLI.

## Inputs

| input | default | meaning |
|---|---|---|
| `version` | `v0.1.8` | CLI release to run, `vX.Y.Z`. Checksum-verified. |
| `command` | `check` | `check` is the gate; `status` reads without gating |
| `dir` | `.` | project root |
| `args` | | extra arguments, e.g. `--fail-on medium --baseline .securechain-baseline` |
| `token` | | TuxCare subscription token; `TUXCARE_TOKEN` in `env` is the usual way |
| `sarif` | `true` | for `check`: write SARIF and upload it to code scanning |
| `fail-on-findings` | `true` | fail the step when the command exits non-zero |

## Outputs

`exit-code` (the CLI's exit code; `1` means findings failed the gate) and
`sarif-file`.

## Exit codes

`0` clean, `1` findings failed the gate, `2` usage, `3` no entitlement, `4`
catalogue unreachable, `5` the toolchain would not resolve. The CLI's own
documentation has the full table.
