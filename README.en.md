# NetGuardian 3.1

**Adaptive route manager for Windows.** NetGuardian finds an IPv4 address that
actually accepts TCP connections for a host name and pins it in the Windows
`hosts` file, so an application stops hanging on `SYN_SENT` / `CLOSE_WAIT`
because of a broken DNS answer or an unreachable CDN edge.

Every change is reversible: the file is written atomically, backed up first,
re-read for verification and rolled back automatically if TLS validation of the
new route fails.

> Plain-text version: [`README.en.txt`](README.en.txt). Russian guide:
> [`README.txt`](README.txt). Copyright and third-party notices:
> [`NOTICE.txt`](NOTICE.txt).

- Version: **3.1.1**
- License: **MIT**
- Platform: Windows 10/11 x64
- Runtime: **no external Python dependencies**

---

## Table of contents

- [What it does](#what-it-does)
- [What it does not do](#what-it-does-not-do)
- [Requirements](#requirements)
- [Install and first run](#install-and-first-run)
- [Quick start](#quick-start)
- [Commands](#commands)
- [Interactive menu](#interactive-menu)
- [Configuration](#configuration)
- [GitHub and GitLab](#github-and-gitlab)
- [Diagnostics](#diagnostics)
- [Troubleshooting](#troubleshooting)
- [Privacy and GDPR](#privacy-and-gdpr)
- [Uninstall](#uninstall)
- [Build from source](#build-from-source)
- [Project layout](#project-layout)
- [Compatibility](#compatibility)
- [License](#license)

---

## What it does

A typical failure looks like this: the internet works, but one application
(launcher, updater, `git`, browser) cannot connect. Diagnostics usually show one
of two things:

- the host name resolves to an address that does not answer on port 443;
- TCP connects, but the TLS handshake fails (interception or a wrong server).

NetGuardian automates one specific, verifiable step:

1. finds an IPv4 address that really accepts TCP on the required port;
2. writes a clearly marked block for the host name into the `hosts` file;
3. verifies the route over TLS (certificate chain, issuer, expiry);
4. automatically rolls the change back if verification fails.

It also includes a connection scanner, a domain diagnostics mode, a TCPView
launcher and a command-line interface with JSON output.

## What it does not do

- It is **not a VPN**, proxy or tunnel. It does not change your IP address.
- It does **not bypass network blocks**. If your provider or the service blocks
  the route at IP level, changing `hosts` will not help.
- It does not modify DNS servers, routes, firewall rules or proxy settings.
- It does not support IPv6 literals for pinning (IPv4 only).
- It does not touch other programs' entries in `hosts`. Only marked
  `NETGUARDIAN FIX` blocks are created or removed.

---

## Requirements

- Windows 10 or Windows 11, 64-bit.
- Administrator rights to modify
  `C:\Windows\System32\drivers\etc\hosts`.
- About 20 MB of disk space for the portable build.
- Python 3.9+ only if you run from source.

Administrator rights are needed for `apply`, `cleanup` and `backups --restore`.
Read-only commands (`scan`, `status`, `validate`, `diag`, `config`) work as a
standard user.

---

## Install and first run

### Portable build (recommended)

The portable build does **not** unpack anything at start-up, so it also works in
locked-down environments where `%TEMP%` is restricted.

1. Extract `NetGuardian-3.1.1-portable-win64.zip` to a folder, for example
   `C:\Tools\NetGuardian`.
2. Right-click `run.cmd` and choose **Run as administrator**.
   You can start `NetGuardian.exe` directly, but `run.cmd` keeps the window open
   on errors and gives the process a writable temporary folder.
3. On first start NetGuardian creates `routes.json` next to the executable with
   four profiles: `microsoft_fix`, `github_access`,
   `gitlab_access`.

Do not move `NetGuardian.exe` away from the `_internal` folder. The portable
build consists of both.

### Single-file build

`NetGuardian-3.1.1-singlefile-win64.zip` contains one `NetGuardian.exe`. At every
start it extracts its libraries into `%TEMP%`. If writing there is blocked
(sandbox, Controlled Folder Access, restrictive policy), the window closes
immediately. In that case use the portable build or `run.cmd`, which redirects
`TEMP` to `%LOCALAPPDATA%\NetGuardian\tmp` and shows the error code.

The executable is not signed with a commercial certificate. Windows SmartScreen
may warn you; choose **More info → Run anyway** and compare the SHA256 with
`SHA256SUMS.txt`.

---

## Quick start

1. Start `run.cmd` as administrator.
2. Choose `[7]` to see the paths and any existing fixes.
3. Choose `[2]`, select a profile, and let NetGuardian resolve and apply it.
4. Choose `[3]` to validate the pinned routes over TLS.
5. Use `[4]` to remove one profile or all NetGuardian blocks.

Command-line equivalent:

```powershell
NetGuardian.exe status
NetGuardian.exe apply github_access
NetGuardian.exe validate github_access
```

---

## Commands

| Command | Purpose |
|---|---|
| `NetGuardian.exe` / `menu` | interactive control center |
| `NetGuardian.exe scan` | find stuck TCP connections and suggest a profile |
| `NetGuardian.exe apply NAME` | resolve addresses and write the profile |
| `NetGuardian.exe apply NAME --dry-run` | show the plan without writing |
| `NetGuardian.exe validate [NAME]` | verify pinned routes over TLS |
| `NetGuardian.exe cleanup NAME` | remove one profile |
| `NetGuardian.exe cleanup --all --yes` | remove every NetGuardian block |
| `NetGuardian.exe status` | active blocks, cache and backups |
| `NetGuardian.exe diag DOMAIN` | DNS/TCP/TLS/proxy diagnostics |
| `NetGuardian.exe backups` | list `hosts` backups |
| `NetGuardian.exe backups --restore 1` | restore a backup |
| `NetGuardian.exe tcpview` | download (signature-checked) and start TCPView |
| `NetGuardian.exe config --check` | validate `routes.json` |
| `NetGuardian.exe config --show` | print the effective configuration |
| `NetGuardian.exe lang en` | switch and persist the UI language |

Global options work before or after the command:

| Option | Meaning |
|---|---|
| `--config PATH` | use a specific `routes.json` |
| `--data-dir PATH` | directory for cache, logs and backups |
| `--hosts PATH` | override the `hosts` path (tests/portable scenarios) |
| `--lang {en,ru,auto}` | interface language |
| `--json` | machine-readable output |
| `--no-color` | disable ANSI colours |
| `--verbose` | mirror the log to the console |

`apply` flags: `--dry-run`, `--force` (ignore conflicting `hosts` lines),
`--no-verify` (skip TLS verification after writing).

Exit codes: `0` success, `1` runtime error, `2` configuration/usage error,
`3` administrator rights required, `4` damaged NetGuardian block in `hosts`.

---

## Interactive menu

| Key | Action |
|---|---|
| `[1]` | scan for stuck connections |
| `[2]` | apply a profile |
| `[3]` | validate routes over TLS |
| `[4]` | remove one or all fixes |
| `[5]` | download and launch TCPView |
| `[6]` | diagnose a domain |
| `[7]` | status: blocks, cache, backups |
| `[8]` | list and restore `hosts` backups |
| `[9]` | settings and paths |
| `[L]` | switch language / Язык |
| `[0]` | exit |

---

## Configuration

`routes.json` is stored next to the executable. If the program directory is
read-only (for example `C:\Program Files`), data moves to
`%LOCALAPPDATA%\NetGuardian`.

### Settings

| Key | Default | Meaning |
|---|---|---|
| `language` | `auto` | `auto`, `en` or `ru` |
| `local_dns` | `""` | IPv4 of a local DNS server; empty = system resolver |
| `dns_timeout_sec` | `3` | DNS query timeout |
| `tcp_timeout_sec` | `3` | TCP probe timeout |
| `cache_ttl_hours` | `6` | cache lifetime; `0` disables the cache |
| `backup_keep` | `10` | number of `hosts` backups to keep |
| `verify_after_apply` | `true` | verify TLS and roll back on failure |
| `stuck_states` | `SYN_SENT`, `CLOSE_WAIT`, `FIN_WAIT_1`, `FIN_WAIT_2`, `LAST_ACK`, `CLOSING` | TCP states treated as stuck |

### Profiles

| Field | Required | Meaning |
|---|---|---|
| `description` | no | menu description |
| `domains` | yes | host names; URLs are accepted and reduced to the host |
| `process_hints` | no | process-name substrings for `scan` |
| `strategy` | no | `static_first`, `dns_discovery_only`, `static_only`, `system_dns` |
| `static_candidates` | for `static_*` | shared IPv4 list tried first |
| `domain_candidates` | no | per-domain IPv4 lists; higher priority than `static_candidates` |
| `expected_issuers` | no | certificate issuer substrings |
| `ports` | no | TCP probe ports, default `[443]` |

Strategies:

- `static_first` — per-domain candidates, then the shared list, then local DNS,
  then the system resolver.
- `dns_discovery_only` — local DNS, then the system resolver.
- `static_only` — only static candidates, no DNS.
- `system_dns` — the system resolver first, then local DNS.

The cache is checked first in every strategy. A cached address is still probed
over TCP and is dropped if it no longer accepts connections.

---

## GitHub and GitLab

Version 3.1 includes `github_access` and `gitlab_access` profiles. They use
`domain_candidates`, because GitHub has different addresses for its web, API,
raw content and archive endpoints.

| Domain | Addresses used as candidates |
|---|---|
| `github.com` | 140.82.121.3, 140.82.121.4, 140.82.112.3, 140.82.113.3, 140.82.114.3 |
| `api.github.com` | 140.82.121.6, 140.82.112.6, 140.82.113.6 |
| `raw.githubusercontent.com` | 185.199.108–111.133 |
| `gist.githubusercontent.com` | 185.199.108–111.133 |
| `codeload.github.com` | 140.82.121.9, 140.82.112.9 |
| `gitlab.com` | 172.65.251.78 |
| `registry.gitlab.com` | 35.227.35.254 |

All of these were verified over TCP and TLS on a test network. The resolver
probes every candidate, so an unreachable address is skipped automatically.

**If `hosts` contains `185.199.108.133 github.com`**, that is a GitHub Pages
address, not the GitHub web front end. TLS may even succeed, but the wrong site
is returned, and the line shadows the NetGuardian block. Remove or comment it out
in Notepad as administrator, then apply the profile.

For EU users with healthy DNS: the bundled GitHub profile prefers known-good
addresses. If you want the nearest edge, set `"strategy": "dns_discovery_only"`
for `github_access` and let your resolver choose.

Commands:

```powershell
NetGuardian.exe diag github.com
NetGuardian.exe cleanup github_access
NetGuardian.exe apply github_access
NetGuardian.exe apply gitlab_access
NetGuardian.exe validate github_access
```

---

## Diagnostics

`NetGuardian.exe diag github.com` checks, in order: `hosts` entries, system DNS,
local DNS, TCP reachability of each address, the TLS certificate (issuer and
expiry) and the system proxy. The result is one of:

| Verdict | Meaning | Action |
|---|---|---|
| `ok` | route looks healthy | nothing |
| `dns` | name does not resolve | check `local_dns`, apply a profile |
| `tcp` | addresses do not answer on 443 | apply a profile, check the network |
| `tls` | TCP works, TLS fails | check proxy/VPN/antivirus |
| `hosts` | a stale `hosts` entry hijacks the name | `cleanup` or edit `hosts` |

`--json` output is intended for scripts and monitoring.

---

## Troubleshooting

**`NetGuardian.exe` does not start / the window closes immediately.**
The single-file build could not extract its libraries into `%TEMP%`. Use the
portable build (`run.cmd` inside the portable folder) or `run.cmd` from the
single-file kit, which redirects `TEMP` to `%LOCALAPPDATA%\NetGuardian\tmp` and
keeps the error visible.

**“Access denied” while writing `hosts`.**
Start as administrator. The interactive menu offers a UAC restart.

**“Existing hosts entry conflicts…”**
`hosts` already maps this domain to a different IP. Remove or comment out the
line, then apply again. `--force` writes the block anyway, but the older line
still wins because Windows uses the first match.

**`validate` reports `UNTRUSTED`.**
TCP works but TLS fails. This usually means a proxy, VPN or antivirus is
intercepting traffic. Check the system proxy in `diag`.

**`apply` reports “no reachable address”.**
No candidate accepted TCP on the configured port. Check the network,
`local_dns`, `static_candidates` and `ports`.

**Browsers ignore `hosts`.**
Chrome, Edge and Firefox may use DNS-over-HTTPS (Secure DNS) and bypass the
system resolver. Disable Secure DNS in the browser or verify with `diag`.

**Old 2.3 blocks are still present.**
They are compatible: `NetGuardian.exe cleanup --all` removes them.

**Installed under `Program Files`.**
Configuration, cache, logs and backups move to `%LOCALAPPDATA%\NetGuardian`.
Writing `hosts` still requires administrator rights.

---

## Privacy and GDPR

NetGuardian is designed as a local, offline-first tool:

- **No telemetry, analytics or crash reporting.**
- **No account, registration or cloud service.**
- **No personal data is collected or transmitted by the application.**
- Outbound traffic is limited to DNS queries, TCP probes and TLS handshakes for
  the domains you explicitly ask it to check, plus an optional HTTPS download of
  TCPView from Microsoft Sysinternals when you choose menu item `[5]`.
- Logs, cache and backups stay in the local data directory and may contain domain
  names and IP addresses. You can delete them at any time; see
  [Uninstall](#uninstall).
- The project is MIT-licensed and provided “as is”, without warranty. You are
  responsible for the `hosts` changes you apply.

For an EU audience: no data controller/processor relationship is created by
using the tool; it runs entirely on the user's machine.

---

## Uninstall

1. Remove NetGuardian blocks from `hosts`:
   ```powershell
   NetGuardian.exe cleanup --all
   ```
2. Delete the program folder.
3. Optionally delete local data:
   `%LOCALAPPDATA%\NetGuardian`.

Backups in `backups\` remain until you delete them.

---

## Build from source

```powershell
python -m unittest discover -s tests -t .   # 108 tests, no network, no admin
.\build.ps1                                  # tests + two builds + ZIPs + SHA256
```

`build.ps1` builds:

- `dist\NetGuardian\` — portable folder with `run.cmd`;
- `dist\NetGuardian.exe` — single file;
- `dist\NetGuardian-3.1.1-portable-win64.zip`;
- `dist\NetGuardian-3.1.1-singlefile-win64.zip`;
- `dist\NetGuardian-3.1.1-source.zip`;
- `dist\SHA256SUMS.txt`.

The icon can be regenerated with `python packaging\make_icon.py` (Pillow
required). PyInstaller is needed only for building the executables.

---

## Project layout

```
NetGuardian-3.1/
├── guardian.py              entry point (python guardian.py)
├── netguardian/             application package (15 modules)
│   ├── cli.py               commands, menu, exit codes
│   ├── config.py            routes.json schema and validation
│   ├── hosts.py             atomic writes, blocks, backups, rollback
│   ├── resolver.py          cache, DNS client, TCP probes
│   ├── scanner.py           netstat/tasklist parser
│   ├── sslcheck.py          TLS certificate inspection
│   ├── diagnostics.py       end-to-end diagnostics
│   ├── tcpview.py           TCPView download and signature check
│   ├── security.py          UAC and Authenticode
│   ├── i18n.py              en/ru catalogs
│   ├── paths.py             portable and %LOCALAPPDATA% modes
│   ├── log.py               rotating logs
│   ├── fsutil.py            atomic file writes
│   ├── errors.py            exception hierarchy
│   └── ui.py                console, colours, tables
├── tests/                   108 unittest tests
├── docs/                    project, architecture, release and audit docs
├── packaging/               version info, run.cmd, icon generator
├── assets/                  icon
├── legacy/                  v2.3 sources for comparison
├── build.ps1                release build
├── NetGuardian.spec         PyInstaller, single file
└── NetGuardian-portable.spec PyInstaller, portable folder
```

---

## Compatibility

- Windows 10/11, Windows Server 2012+.
- Python 3.9+ when running from source (developed and tested on 3.12).
- Standard library only at runtime. Pillow is needed only to regenerate the
  icon; PyInstaller is needed only to build the executables.
- The 2.x cache format is read automatically and rewritten in the current format.
- `routes.json` and the `NETGUARDIAN FIX` block markers are compatible with 2.3.

---

## License

MIT. See [LICENSE](LICENSE).
