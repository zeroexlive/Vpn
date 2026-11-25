# FeiLian Client — C rewrite (login + connect only)

A small C client for FeiLian / CorpLink (ByteDance Volcano Engine,
SealSuite), built with [CUI](https://github.com/yappologistic/CUI)
(MIT, C99, no dependencies) for the UI and OpenSSL for HTTPS.

It does **login and VPN connect only**. It does not implement the
official client's endpoint-security / device-baseline / DLP sections,
and it does not bypass them — if your server requires them, login or
`/vpn/conn` will fail and the server's error is shown in the log.

## What was found by reversing the official client

Package analysed (static inspection only, never installed or run):
`FeiLian_Linux_amd64_v3.2.16_r8362_0d182a.deb`
— `com.volcengine.feilian` 3.2.16, 239 MB, SHA-256
`0ecaf5a41960a35679d1a715b73dadab1703b65decf13dbd689f8e1cc946a9d3`

- Electron UI (`corplink`, 156 MB, `resources/app.asar` 101 MB)
  launched by `/usr/local/bin/Corplink`
- `corplink-service` (25 MB, Go) — the daemon, run by
  `corplink.service`, talking to NetworkManager / dnsmasq
- `bin/corplink-uc`, `bin/corplink-security` — the security helpers
  this rewrite deliberately does **not** reimplement

Endpoints, confirmed in the .deb strings and in the public
corplink-go / corplink-rs clients:

| Step | Call |
|---|---|
| Company → server | `POST https://corplink.volcengine.cn/api/match` `{"code": "<company>"}` |
| Login method | `GET {server}/api/login/setting?os={os}&os_version={ver}` |
| Login (password) | `POST {server}/api/login?os={os}&os_version={ver}` `{"user_name": "…", "password": "<sha256 hex>", "platform": "feilian"}` |
| List VPN | `GET {server}/api/vpn/list?os={os}&os_version={ver}` |
| Fetch WireGuard peer | `POST {server}/vpn/conn?os={os}&os_version={ver}` `{"public_key": "…"}` |
| Keep-alive / disconnect | `POST {server}/vpn/report?os={os}&os_version={ver}` |

The `os` / `os_version` query parameters are how the server picks
the login method. The UI asks for the OS **before login**, defaulting
to the OS this binary is actually running on (Linux here). Send the
value your deployment enrolled this device / account for.

Passwords are SHA-256 hexed before sending (matching corplink-go),
never written to disk. Cookies are kept in memory only.

## Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/feilian-client
```

Needs a C99 compiler, CMake ≥ 3.14, OpenSSL dev headers, and on
Linux `libx11-dev`. CUI is fetched at configure time (v1.5.0).

## Use

1. Choose the OS to report, **before** logging in.
2. Enter a company code (resolved via `/api/match`) or paste the
   server URL directly, then username and password.
3. **Log in** — the log shows `login/setting`, then `login`.
4. **List VPN servers** — raw `/api/vpn/list` reply in the log.
5. **Connect** — generates a WireGuard keypair, calls `/vpn/conn`,
   and writes `corplink.conf` in the current directory when the
   server returns a peer. Bring the tunnel up with root +
   wireguard-tools on the target machine:
   `sudo wg-quick up corplink.conf`

## Status / limits

- v2: company lookup fixed — the `/api/match` reply carries the
  server in `data.domain` (not `url`), the client now uses the
  corplink-go User-Agent, honours `https_proxy`/`HTTPS_PROXY`
  (CONNECT tunnel) for proxied networks, and shows the server's
  full reply body on a lookup failure instead of just the HTTP code.
  A wrong company code returns HTTP 200 with code 1005
  ("The enterprise identification code does not exist"); a 403
  means the request was blocked before lookup (WAF / proxy / IP
  geo-block), not a wrong code. Workaround: paste the server URL
  directly (e.g. `https://<name>.ifeilian.cn:443`) to skip `/api/match`.
- Not yet: automatic `wg-quick` bring-up (needs root + `wg` on the
  target), keep-alive reporting (`/vpn/report`), MFA / email-code /
  TOTP login flows, LDAP / Lark / OIDC platforms. The official UI
  (see screenshot) shows a One-Time Password, so deployments with
  MFA will need the OTP step after password login.
- The peer reply is nested JSON; the top-level field extraction in
  `src/main.c` is best-effort — if your server's shape differs, paste
  the logged `/vpn/conn` reply and the parser can be adjusted to it.
- To test login you need a real server URL / company code and
  credentials for a deployment you are allowed to use. None are
  stored in this repo.
