# chitin

On-access malware scanning for Linux, in Rust.

`chitin` hooks execution through the kernel's fanotify permission API, scans the
target with [YARA-X](https://github.com/VirusTotal/yara-x), and returns an
allow/deny verdict before the process is allowed to run. A blocked binary never
executes — the `execve` fails with `EPERM`.

It exists because ClamAV is heavy and signature-only, while the lighter Linux
options (Falco, Tetragon, Tracee) watch behaviour but don't block a file on
content. `chitin` covers the file half: a small, fast on-access scanner meant to
sit alongside an eBPF behavioural tool rather than replace one.

## Status

Working, minimal. It compiles, blocks real executions, and caches verdicts. It
is not a managed EDR — no telemetry pipeline, no quarantine, no central console.

## Requirements

- Linux kernel 5.0+ (`FAN_OPEN_EXEC_PERM`)
- `CAP_SYS_ADMIN` (run as root)
- Rust 1.87+ (to build from source)

## Install

Prebuilt binaries are on the [releases page](https://github.com/cdmx-in/chitin/releases)
for x86_64 and aarch64:

| Build | Runs on |
|---|---|
| `*-linux-gnu` | glibc 2.35+ — Ubuntu 22.04, 24.04 |
| `*-linux-musl` | statically linked, any distro including Ubuntu 20.04 |

Take the musl build if you are unsure — it has no libc dependency at all.

```sh
tar xzf chitin-<version>-x86_64-unknown-linux-musl.tar.gz
sudo ./chitin /etc/chitin/rules /
```

## Build

```sh
cargo build --release
```

## Run

```sh
sudo ./target/release/chitin <rules-dir> [mount-point]
```

`<rules-dir>` is a directory of `.yar`/`.yara` files. `[mount-point]` defaults to
`/` — the whole filesystem is watched. Point it at a specific mount to narrow
scope.

```sh
sudo ./target/release/chitin /etc/chitin/rules /srv
```

Denials are printed to stdout with the matching rule name:

```
chitin: DENY pid=19387 /srv/upload/mal.sh [chitin_selftest_marker]
```

## Rules

Any YARA ruleset works. [YARA Forge](https://yarahq.github.io/) packages curated
public rules from ReversingLabs, Elastic, ESET, and Mandiant into three tiers —
start with the Core set, which is tuned for a low false-positive rate.

## Design notes

- **Fails open.** A scan error, read error, or unstattable file is *allowed*, not
  blocked. A rules bug should not make a machine unbootable.
- **Verdicts are cached** by `(dev, ino, mtime, size)`, so `/bin/sh` is scanned
  once rather than on every exec.
- **Files over 32 MB are skipped**, not scanned.
- **Self-execs are never adjudicated** — the scanner deciding on its own
  `execve` deadlocks it.

## Tests

```sh
cargo test
```

Covers the verdict decision (a matching rule must deny, clean content must
allow) and the read cap. The end-to-end behaviour — that a denied binary
actually fails to execute — needs root and a live kernel; see the tmpfs
procedure in the commit history.

## License

Copyright © Codemax IT Solutions Pvt. Ltd.
