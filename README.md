# SecureChain GitHub Action

Runs the [SecureChain CLI](https://securechain.tuxcare.com) gate against your
repository and uploads its findings to GitHub code scanning.

This repository holds no CLI source. The action downloads the released binary
for a **pinned** version through the same install script every customer uses,
verifies its checksum against the release's `checksums.txt` before anything
runs, then runs `securechain check`. The default version is the release this
action was published with: `v0.1.16`.

With `command: registry` the action writes the registry credential into a
directory for the job, for the job's own install step, and runs no gate. A
workflow runs it before its install, and runs the action again after the
install for the gate: the install needs the credential, and `check` needs
the installed tree.

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
      # The credential first: npm ci reads it from the job directory.
      - uses: TuxCare/securechain-action@v0
        with:
          command: registry
          portal-token: ${{ secrets.SECURECHAIN_PORTAL_TOKEN }}
      - run: npm ci
      # Then the gate, over the installed tree. `if: always()` runs it after
      # a failed install too: its last step removes the job's credential.
      - uses: TuxCare/securechain-action@v0
        if: always()
        with:
          portal-token: ${{ secrets.SECURECHAIN_PORTAL_TOKEN }}
          registry-login: none
```

`@v0` follows the newest release of the 0.x line; `@v0.1.16` pins one
release of the action, which pins one release of the CLI.

Before the command, the action runs `securechain registry env --job-dir` into
`$RUNNER_TEMP/securechain-job`, masks each value, and exports to the job
`TUXCARE_TOKEN` and the variables that name the directory's two files:
`NPM_CONFIG_USERCONFIG` for npm, pnpm and yarn classic, and `NETRC` for pip,
pipenv, pdm, uv and poetry (doc 03, "securechain registry"; doc 99 Q81,
Q82). A later step's `npm ci` or `pip install` in the same job reads the
credential from there, and `~/.npmrc` and `~/.netrc` stay as they were. That
is why the install step comes after the `command: registry` use, and the
gate's use sets `registry-login: none`: the credential is in place, and the
gate needs no second read. `registry-login: none` also suits a tenant whose
registry credential nobody has set yet: `check` needs none, and the
credential step would stop the job at exit 3.

yarn berry and bun read neither file. For a yarn berry project, a `dir` with
`.yarnrc.yml` or a berry `yarn.lock`, the action also writes a
`${TUXCARE_TOKEN:-}` reference into `~/.yarnrc.yml`, which stops no other
project while the variable is unset, with `--keep-source`, so berry's source
there stays as it was. For a bun project, a `dir` with
`bun.lock` or `bun.lockb`, it keeps a copy of bun's `.npmrc` in the job
directory and writes the token into the file (doc 99 Q91), but only when
no entry of `bun.lock` would send it to another host (doc 99 Q93): a
package that resolves through the TuxCare registry with its URL elsewhere, or a
GitHub or git dependency. A scope you route to your own registry, and a tarball
dependency, do not count. Otherwise bun gets no credential, and the log says
which host `bun.lock` names and to re-resolve the lockfile against the
registry. A project with
only `bun.lockb` gets none either: write `bun.lock` with `bun install
--save-text-lockfile`. When bun's `.npmrc` is a symbolic link, the step writes
nothing through it, says so, and bun gets no credential. The action's last
step puts the file back and removes the job directory. It runs in the gate's
use, so give that use `if: always()`: a failed install skips it otherwise. The
runner empties `$RUNNER_TEMP` after each job, but a self-hosted runner keeps
its home directory, and bun's `.npmrc` with it.

## Inputs

| input | default | meaning |
|---|---|---|
| `version` | `v0.1.16` | CLI release to run, `vX.Y.Z`. Checksum-verified. |
| `command` | `check` | `check` is the gate; `status` reads without gating; `registry` writes the job directory for a later install step and runs no gate |
| `dir` | `.` | project root |
| `args` | | extra arguments, e.g. `--fail-on medium --baseline .securechain-baseline` |
| `portal-token` | (required) | TuxCare portal token, passed to the CLI as `SECURECHAIN_PORTAL_TOKEN` |
| `registry-login` | `job-dir` | `job-dir` writes the job directory and exports its variables, and gives a berry or a bun project its own step; `none` writes and exports nothing, and is refused with `command: registry`. `reference` and `plain`, the routes until 28 September 2026, are refused |
| `sarif` | `true` | for `check`: write SARIF and upload it to code scanning |
| `fail-on-findings` | `true` | fail the step when the command exits non-zero |

## Outputs

`exit-code` (the CLI's exit code; `1` means findings failed the gate) and
`sarif-file`.

## Exit codes

`0` clean, `1` findings failed the gate, `2` usage, `3` auth (no token, or
the portal refused the token, the tenant or the registry-credential
request), `4` portal (the portal could not give data the tool can trust:
unreachable, `5xx`, stale, or an answer that failed a check), `5` the
toolchain would not resolve. The CLI's own documentation (doc 03, "Exit
codes") has the full table.
