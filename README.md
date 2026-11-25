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
| Company → server | `POST https://corplink.isealsuite.com/api/match?language=en` `{"code": "<company>"}` (legacy fallback: `corplink.volcengine.cn/api/match`). Reply `data.domain` is the server; `enable_self_signed` / `self_signed_cert` are the corp cert to trust for TLS to it. |
| Login method | `GET {server}/api/login/setting` (no query params) |
| Login (password) | `POST {server}/api/v1/login` `{"login_scene": "feilian", "account_type": "email", "account": "…", "password": "<aesEncryptIv(password)>"}` |
| List VPN | `GET {server}/api/vpn/list` (legacy path; 3.2.16 UI uses the local service `getVpnList`) |
| Fetch WireGuard peer | `POST {server}/vpn/conn` `{"public_key": "…", "otp": "…"}` (legacy path; 3.2.16 UI uses `connectVpn`) |
| Keep-alive / disconnect | `POST {server}/vpn/report` |

The reply to login is a double envelope: outer `code`, inner
`data` is a JSON string, and `data.next.action` decides the next
screen (`main` = logged in, `2FA` = second factor,
`ChangeInitPassword`, `SelectUser`, …). A failure stays on the
login screen with the server's message — never a 2FA screen after
a failure.

**Password encryption:** the server's setting says
`"password_encrypted":true`, and the official client encrypts
with `aesEncryptIv` / the portal's `aesEncrypt`. The algorithm
is in the portal's public web JS (portal 3.3.14, module 90949),
not hidden in the native module:
`key = MD5("9007199254740991")` as hex (32 chars, UTF-8 =
AES-256 key), `iv = first 16 chars of SHA1(key)` as ASCII,
AES-256-CBC with PKCS#7, output lowercase hex, no IV
prepended. This client implements exactly that
(`feilian_aes_encrypt_password`). Verified: a plain password
is rejected by `ourbit.sealsuite.com` with `40000 Parameter
is invalid`, while this encryption is accepted as a parameter
(`10110001` "user name or password is incorrect" for a dummy
account). The native bridge's `aesEncryptIv` produces the
same deterministic hex format.

The OS picker is kept for the legacy endpoints that still take
`os`/`os_version`; the 3.2.16 login calls take no `os` param.

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
   server URL directly, press Next, then enter email and password
   and press Log in. There is no second factor at login — SealSuite
   checks email/password and, if correct, you go to the main layout.
3. Main layout: press Connect. Two MFA ways, as in the official app:
   - Enter the 6-digit OTP from your mobile app (e.g. 617928) —
     sent as `"otp"` in `POST /vpn/conn`. If the server returned a
     TOTP secret via `GET /api/v2/p/otp` after login, the code is
     generated locally (RFC 6238, server-time offset) and the field
     can be left empty.
   - Confirm on mobile app (push): the client asks `/api/mfa/type`,
     and if `push` is offered it sends a push request, you approve
     it on your mobile app, then press Connect. Note: in the
     official client push goes through corplink-service
     `sendPushConfirm {scene:"vpn"}`; if your server does not offer
     push over HTTP, use the OTP way.
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
- v4: "HTTP -1" is now a plain-English transport error instead of a
  bare code, with 10 s connect / 15 s read timeouts (it used to hang
  for minutes). E.g. "TLS handshake failed to corplink.volcengine.cn
  — server may require a proxy, or TLS is blocked", "DNS lookup
  failed", "TCP connect timed out", "proxy refused CONNECT".
  There is also a Proxy field on the first screen
  (`http://user:pass@proxy:3128`); otherwise `https_proxy` from the
  environment is used. If you get a TLS/connect error, first test
  in a terminal:
  `curl -X POST https://corplink.volcengine.cn/api/match -H 'Content-Type: application/json' -d '{"code":"test"}'`
  — if curl fails too, the network blocks the server; if curl works
  but the client does not, launch the client from that same terminal
  so it inherits the proxy settings.
- v3: staged UI (company → email/password → main layout), OTP at
  Connect (`"otp"` in `/vpn/conn`), TOTP generation from
  `/api/v2/p/otp`, login MFA (`/api/v1/login/mfa/send` +
  `/verify`, types otp/email/mobile/push/password), push confirm
  via `/api/mfa/type` + `mfa/send push`.
- Not yet: automatic `wg-quick` bring-up (needs root + `wg` on the
  target), keep-alive reporting (`/vpn/report`), LDAP / Lark / OIDC
  platforms.
- The peer reply is nested JSON; the top-level field extraction in
  `src/main.c` is best-effort — if your server's shape differs, paste
  the logged `/vpn/conn` reply and the parser can be adjusted to it.
- To test login you need a real server URL / company code and
  credentials for a deployment you are allowed to use. None are
  stored in this repo.
