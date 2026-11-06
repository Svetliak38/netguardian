================================================================================
 NETGUARDIAN 3.1
 Adaptive route manager for Windows
 User guide (English)
================================================================================

Version:      3.1.4
License:      MIT
Author:       Svetliak
Document:     README.en.txt

Detailed technical documentation:
  docs\HOW-IT-WORKS.txt   architecture, algorithms, formats
  docs\PROJECT.txt        project description and results
  docs\RELEASE.txt        release contents and checklist
  README.en.md            the same guide in Markdown format

Russian guide:
  README.txt


--------------------------------------------------------------------------------
1. WHAT IT IS
--------------------------------------------------------------------------------

NetGuardian helps when an application cannot connect even though the internet
works: it hangs on "connecting", reports a network error or times out.

A common cause is that a host name resolves to an IPv4 address that does not
accept TCP connections (or accepts them but TLS fails). NetGuardian:

  1) finds an address that really accepts TCP on the required port;
  2) pins it to the host name in the Windows hosts file;
  3) verifies the new route over TLS (certificate chain, issuer, expiry);
  4) rolls the change back automatically if verification fails.

Every change is reversible. NetGuardian writes clearly marked blocks, makes a
backup before each write and removes only its own blocks.

WHAT IT DOES NOT DO:

  - It is not a VPN, proxy or tunnel and does not change your IP address.
  - It does not bypass network blocks. If your provider or the service blocks
    the route at IP level, editing hosts will not help.
  - It does not change DNS servers, routes, firewall or proxy settings.
  - It pins IPv4 addresses only (no IPv6 literals).
  - It does not touch other programs' entries in hosts.


--------------------------------------------------------------------------------
2. REQUIREMENTS
--------------------------------------------------------------------------------

  - Windows 10 or Windows 11, 64-bit.
  - Administrator rights to edit:
        C:\Windows\System32\drivers\etc\hosts
  - About 20 MB of disk space for the portable build.
  - Python 3.9+ only when running from source.

Administrator rights are required for apply, cleanup and restore. The commands
scan, status, validate, diag and config work as a standard user.


--------------------------------------------------------------------------------
3. INSTALL AND FIRST RUN
--------------------------------------------------------------------------------

3.1. PORTABLE BUILD (RECOMMENDED)
---------------------------------

The portable build does not unpack anything at start-up, so it works even when
the TEMP directory is restricted.

1) Extract NetGuardian-3.1.1-portable-win64.zip to a folder, for example:
       C:\Tools\NetGuardian

2) Right-click run.cmd and choose "Run as administrator".
   You can start NetGuardian.exe directly, but run.cmd:
     - keeps the window open if the program fails;
     - gives the process a writable temporary folder.

3) On first start NetGuardian creates routes.json next to the executable with
   four profiles:
       microsoft_fix, github_access, gitlab_access

IMPORTANT: do not move NetGuardian.exe away from the _internal folder.
The portable build consists of both.


3.2. SINGLE-FILE BUILD
----------------------

NetGuardian-3.1.1-singlefile-win64.zip contains one NetGuardian.exe. At every
start it extracts its libraries into %TEMP%. If writing there is blocked
(sandbox, Controlled Folder Access, restrictive policy), the window closes
immediately.

In that case:
  - use the portable build; or
  - run run.cmd, which redirects TEMP to %LOCALAPPDATA%\NetGuardian\tmp and
    shows the error code without closing the window.

The executable is not signed with a commercial certificate. Windows SmartScreen
may warn you: choose "More info" -> "Run anyway" and compare the SHA256 with
SHA256SUMS.txt.


3.3. FIRST START
----------------

If the program directory is read-only (for example C:\Program Files), the
configuration, cache, logs and backups move automatically to:
    %LOCALAPPDATA%\NetGuardian


--------------------------------------------------------------------------------
4. INTERACTIVE MENU
--------------------------------------------------------------------------------

  [1] Scan for stuck connections
      Reads the Windows TCP table and looks for processes stuck in SYN_SENT,
      CLOSE_WAIT, FIN_WAIT_1/2 and similar states.

  [2] Apply a profile
      Select a profile. NetGuardian resolves a working address for every
      domain, writes the block and verifies it over TLS. On failure the
      change is rolled back.

  [3] Validate routes (TLS)
      Checks each profile domain over TLS using the pinned address.

  [4] Clean up fixes
      Removes one profile or all NetGuardian blocks. Other entries in hosts
      are not touched.

  [5] Launch TCPView
      Downloads TCPView from Microsoft Sysinternals, verifies its digital
      signature and starts it. Unsigned files are refused by default.

  [6] Diagnose a connection
      Checks hosts entries, system DNS, local DNS, TCP, TLS and the system
      proxy, then prints a verdict and a recommendation.

  [7] Status and active fixes
      Shows paths, active blocks, cached addresses and backup count.

  [8] Backups and restore
      Lists hosts backups and restores a selected one.

  [9] Settings
      Shows paths and parameters and can open the data folder.

  [L] Switch language / Язык
      Switches English and Russian; the choice is saved in routes.json.

  [0] Exit


--------------------------------------------------------------------------------
5. COMMAND LINE
--------------------------------------------------------------------------------

All menu actions are available as commands.

  NetGuardian.exe status
  NetGuardian.exe scan
  NetGuardian.exe apply github_access
  NetGuardian.exe apply github_access --dry-run
  NetGuardian.exe validate
  NetGuardian.exe diag github.com
  NetGuardian.exe cleanup --all --yes
  NetGuardian.exe backups --restore 1
  NetGuardian.exe config --check
  NetGuardian.exe lang en
  NetGuardian.exe --help
  NetGuardian.exe --version

MAIN COMMANDS:

  scan                 find stuck TCP connections
  apply NAME           apply a profile
  validate [NAME]      verify routes over TLS
  cleanup NAME         remove one profile
  cleanup --all        remove every NetGuardian block
  status               show blocks, cache and backups
  diag DOMAIN          diagnose a domain
  backups              list hosts backups
  backups --restore N  restore a backup by number or name
  tcpview              download and start TCPView
  config --check       validate routes.json
  config --show        print the effective configuration
  lang en|ru|auto      switch the interface language

GLOBAL OPTIONS:

  --config PATH        use a specific routes.json
  --data-dir PATH      directory for cache, logs and backups
  --hosts PATH         override the hosts path (tests/portable scenarios)
  --json               machine-readable output
  --no-color           disable ANSI colours
  --verbose            mirror the log to the console

APPLY FLAGS:

  --dry-run            show the plan without writing
  --force              ignore conflicting hosts lines
  --no-verify          skip TLS verification after writing

EXIT CODES:

  0  success
  1  runtime error (no address, TLS failure, etc.)
  2  configuration or usage error
  3  administrator rights required
  4  damaged NetGuardian block in hosts


--------------------------------------------------------------------------------
6. CONFIGURATION
--------------------------------------------------------------------------------

routes.json is stored next to the executable (or in %LOCALAPPDATA%\NetGuardian
when the program directory is read-only).

6.1. SETTINGS
-------------

  language            "auto", "en" or "ru"; default "auto"
  local_dns           IPv4 of a local DNS server; empty = system resolver
  dns_timeout_sec     DNS query timeout, 1..30
  tcp_timeout_sec     TCP probe timeout, 1..30
  cache_ttl_hours     cache lifetime; 0 disables the cache
  backup_keep         number of hosts backups to keep, 1..100
  verify_after_apply  true/false: verify TLS and roll back on failure
  stuck_states        TCP states treated as stuck

6.2. PROFILES
-------------

  description         menu description
  domains             host names; URLs are accepted and reduced to the host
  process_hints       process-name substrings for scan
  strategy            how to find an address (see below)
  static_candidates   shared IPv4 list tried first
  domain_candidates   per-domain IPv4 lists; higher priority
  expected_issuers    certificate issuer substrings
  ports               TCP probe ports; default [443]

STRATEGIES:

  static_first        domain_candidates, then static_candidates, then local
                      DNS, then the system resolver
  dns_discovery_only  local DNS, then the system resolver
  static_only         only static candidates, no DNS
  system_dns          the system resolver first, then local DNS

The cache is checked first in every strategy. A cached address is still probed
over TCP and dropped if it no longer accepts connections.

6.3. EXAMPLE
------------

  "github_access": {
    "domains": ["github.com", "api.github.com",
                "raw.githubusercontent.com"],
    "strategy": "static_first",
    "domain_candidates": {
      "github.com": ["140.82.121.3", "140.82.112.3"],
      "api.github.com": ["140.82.121.6"],
      "raw.githubusercontent.com": ["185.199.108.133"]
    },
    "expected_issuers": ["Sectigo", "DigiCert", "Let's Encrypt"],
    "ports": [443]
  }


--------------------------------------------------------------------------------
7. GITHUB AND GITLAB
--------------------------------------------------------------------------------

Version 3.1 includes github_access and gitlab_access profiles. They use
domain_candidates because GitHub has different addresses for its web, API,
raw content and archive endpoints.

  github.com                  140.82.121.3, 140.82.121.4, 140.82.112.3,
                              140.82.113.3, 140.82.114.3
  api.github.com              140.82.121.6, 140.82.112.6, 140.82.113.6
  raw.githubusercontent.com   185.199.108-111.133
  gist.githubusercontent.com  185.199.108-111.133
  codeload.github.com         140.82.121.9, 140.82.112.9
  gitlab.com                  172.65.251.78
  registry.gitlab.com         35.227.35.254

All candidates are probed over TCP; unreachable addresses are skipped.

IF HOSTS CONTAINS "185.199.108.133 github.com", that is a GitHub Pages
address, not the GitHub web front end. TLS may even succeed, but the wrong site
is returned and the line shadows the NetGuardian block. Remove or comment it out
in Notepad as administrator, then apply the profile.

For EU users with healthy DNS: the bundled GitHub profile prefers known-good
addresses. If you want the nearest edge, set "strategy": "dns_discovery_only"
for github_access and let your resolver choose.

COMMANDS:

  NetGuardian.exe diag github.com
  NetGuardian.exe cleanup github_access
  NetGuardian.exe apply github_access
  NetGuardian.exe apply gitlab_access
  NetGuardian.exe validate github_access

If your provider or the service blocks the route at IP level, hosts will not
help. NetGuardian does not change your IP address and is not a VPN.


--------------------------------------------------------------------------------
8. SAFETY AND ROLLBACK
--------------------------------------------------------------------------------

For every change NetGuardian:

  - creates a backup of hosts in the backups folder;
  - writes a temporary file and replaces hosts atomically;
  - re-reads the file and verifies the block;
  - restores the previous version if verification fails;
  - leaves other profiles' blocks and other programs' entries untouched.

MARKER FORMAT:

  # === NETGUARDIAN FIX (profile) [timestamp] BEGIN ===
  IP domain
  # === NETGUARDIAN FIX (profile) [timestamp] END ===

Old 2.3 blocks use the same format and are compatible.

CONFLICTS:

Windows uses the first match in hosts. If an older line maps the same domain to
a different IP, the new block cannot win. NetGuardian detects such lines and
refuses to write until they are removed or commented out. --force writes the
block anyway, but the older line may still win; use it deliberately.


--------------------------------------------------------------------------------
9. TROUBLESHOOTING
--------------------------------------------------------------------------------

9.1. NetGuardian.exe does not start / the window closes immediately
--------------------------------------------------------------------
The single-file build could not extract its libraries into %TEMP%. Use the
portable build (run.cmd) or run.cmd from the single-file kit, which redirects
TEMP to %LOCALAPPDATA%\NetGuardian\tmp.

9.2. "Access denied" while writing hosts
----------------------------------------
Start as administrator. The interactive menu offers a UAC restart.

9.3. "Existing hosts entry conflicts..."
----------------------------------------
hosts already maps this domain to a different IP. Remove or comment out the
line, then apply again.

9.4. validate reports UNTRUSTED
-------------------------------
TCP works but TLS fails. Usually a proxy, VPN or antivirus is intercepting
traffic. Check the system proxy in diag.

9.5. apply reports "no reachable address"
-----------------------------------------
No candidate accepted TCP on the configured port. Check the network, local_dns,
static_candidates and ports.

9.6. Browsers ignore hosts
--------------------------
Chrome, Edge and Firefox may use DNS-over-HTTPS (Secure DNS) and bypass the
system resolver. Disable Secure DNS in the browser or verify with diag.

9.7. Old 2.3 blocks are still present
-------------------------------------
They are compatible: NetGuardian.exe cleanup --all removes them.

9.8. Installed under Program Files
----------------------------------
Configuration, cache, logs and backups move to %LOCALAPPDATA%\NetGuardian.
Writing hosts still requires administrator rights.


--------------------------------------------------------------------------------
10. PRIVACY AND GDPR
--------------------------------------------------------------------------------

NetGuardian is a local, offline-first tool:

  - no telemetry, analytics or crash reporting;
  - no account, registration or cloud service;
  - no personal data is collected or transmitted by the application;
  - outbound traffic is limited to DNS queries, TCP probes and TLS handshakes
    for the domains you explicitly ask it to check, plus an optional HTTPS
    download of TCPView from Microsoft Sysinternals when you choose menu [5];
  - logs, cache and backups stay in the local data directory and may contain
    domain names and IP addresses; delete them at any time.

The project is MIT-licensed and provided "as is", without warranty. You are
responsible for the hosts changes you apply. Using the tool does not create a
data controller/processor relationship; it runs entirely on the user's machine.


--------------------------------------------------------------------------------
11. DATA LOCATIONS
--------------------------------------------------------------------------------

  routes.json         settings and profiles
  cache_ips.json      cached addresses
  logs\               netguardian.log, rotated at 1 MB x 3
  backups\            hosts-*.bak

Everything is stored next to the executable. If the directory is read-only,
use %LOCALAPPDATA%\NetGuardian.


--------------------------------------------------------------------------------
12. UNINSTALL
--------------------------------------------------------------------------------

1) Remove NetGuardian blocks from hosts:
       NetGuardian.exe cleanup --all

2) Delete the program folder.

3) Optionally delete local data:
       %LOCALAPPDATA%\NetGuardian

Backups in the backups folder remain until you delete them.


--------------------------------------------------------------------------------
13. VERIFY SHA256
--------------------------------------------------------------------------------

SHA256SUMS.txt contains the checksums of the release files. In PowerShell:

    Get-FileHash .\NetGuardian.exe -Algorithm SHA256

Compare the value with SHA256SUMS.txt. For an archive, verify the ZIP file
itself the same way.


--------------------------------------------------------------------------------
14. BUILD AND TEST
--------------------------------------------------------------------------------

From source:

    python -m unittest discover -s tests -t .   # 108 tests, no network, no admin
    .\build.ps1                                  # builds both variants and ZIPs

Requirements for building: Python 3.9+, PyInstaller 6+, Pillow (icon only).
The application itself uses only the Python standard library.


--------------------------------------------------------------------------------
15. LICENSE AND COPYRIGHT
--------------------------------------------------------------------------------

NetGuardian 3.1
Copyright (c) 2026 Svetliak

MIT License. See LICENSE.

Third-party components:

  - Python runtime, PSF License (bundled in the EXE).
  - PyInstaller bootloader, GPLv2 with a special exception (build tool).
  - TCPView is not bundled; it is downloaded from Microsoft Sysinternals only
    when the user chooses menu [5], and remains subject to Microsoft's terms.

Windows and Microsoft are trademarks of Microsoft Corporation. GitHub and
GitLab are trademarks of their respective owners. NetGuardian is not affiliated
with Microsoft, GitHub or GitLab.

See NOTICE.txt for details.


================================================================================
 End of document.
================================================================================
