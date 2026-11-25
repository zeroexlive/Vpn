#ifndef FEILIAN_H
#define FEILIAN_H

#include <stddef.h>

/* FeiLian / CorpLink login + VPN list + WireGuard peer flow.
 *
 * Endpoints confirmed two ways:
 *  - strings in the official 3.2.16 Linux .deb (Electron UI + corplink-service):
 *    /api/v1/login, /api/login/setting, /api/vpn/list, /api/matchinternal
 *  - the public corplink-go / corplink-rs clients, which implement the same
 *    flow: https://github.com/kongfei605/corplink-go (api.go / client.go)
 *      POST https://corplink.volcengine.cn/api/match  {"code": "<company>"}
 *      GET  {server}/api/login/setting?os={os}&os_version={ver}
 *      POST {server}/api/login?os={os}&os_version={ver}
 *           {"user_name": "...", "password": "<sha256 hex>", "platform": "feilian"}
 *      GET  {server}/api/vpn/list?os={os}&os_version={ver}
 *      POST {server}/vpn/conn?os={os}&os_version={ver}   (fetch WireGuard peer)
 *      POST {server}/vpn/report?os={os}&os_version={ver} (keep-alive / disconnect)
 *
 * This is a login-and-connect client only. It does not implement the
 * endpoint-security / device-baseline / DLP parts of the official client,
 * and it does not bypass them: if the server requires them, login or
 * /vpn/conn will fail and the server's error is shown verbatim.
 *
 * The `os` query parameter is the platform the server uses to pick the
 * login method. The UI lets you pick it BEFORE login, defaulting to the
 * OS this binary is actually running on. Send the value your deployment
 * enrolled this device/account for.
 */

#define FEILIAN_MATCH_URL "https://corplink.volcengine.cn/api/match"
/* Same UA as the public corplink-go client — the server/WAF accepts it. */
#define FEILIAN_USER_AGENT "CorpLink/201000 (GooglePixel; Android 10; en)"

typedef struct {
    char server[512];      /* e.g. https://xxx.feilian.volcengine.cn, from /api/match */
    char company[128];     /* company code, used only for /api/match */
    char username[128];
    char os[32];           /* "Linux" | "Windows" | "Mac" | "Android" */
    char os_version[32];   /* e.g. "2" (corplink-go) — keep as the server expects */
    char device_name[128];
    char cookies[4096];    /* Cookie: header value, accumulated from Set-Cookie */
    char totp_secret[128]; /* base32 TOTP secret from /api/v2/p/otp, if any */
    long date_offset_sec;  /* server Date minus local time, for TOTP */
    char last_error[512];  /* set by feilian_https on transport failure */
    int logged_in;
} feilian_client;

/* Append a line to a log buffer (used by the UI). */
void feilian_log(char *log, size_t cap, const char *fmt, ...);

/* HTTPS GET/POST. Returns HTTP status, or -1 on transport error.
 * body is NUL-terminated JSON/text, truncated to cap-1. Cookies are
 * accumulated into c->cookies. TLS verification is ON (unlike
 * corplink-go, which sets InsecureSkipVerify). */
int feilian_https(feilian_client *c, const char *method, const char *url,
                  const char *json_body, char *body, size_t cap);

/* Resolve company code -> server URL via /api/match. */
int feilian_match_company(feilian_client *c, char *err, size_t err_cap);

/* GET /api/login/setting — shows which login methods the server offers. */
int feilian_login_setting(feilian_client *c, char *body, size_t cap);

/* POST /api/login — password is SHA-256 hexed first unless it is
 * already 64 hex chars, matching corplink-go. */
int feilian_login_password(feilian_client *c, const char *password,
                           char *body, size_t cap);

/* GET /api/vpn/list */
int feilian_list_vpn(feilian_client *c, char *body, size_t cap);

/* POST /vpn/conn — ask the server for a WireGuard peer for our public key. */
int feilian_fetch_peer(feilian_client *c, const char *vpn_base_url,
                       const char *public_key, char *body, size_t cap);

/* Same, with the 6-digit OTP from the mobile app (TOTP code, e.g.
 * "617928"). Pass "" / NULL to omit it. The official flow asks for
 * this OTP at Connect time, after login. */
int feilian_fetch_peer_otp(feilian_client *c, const char *vpn_base_url,
                           const char *public_key, const char *otp,
                           char *body, size_t cap);

/* GET /api/v2/p/otp — returns an otpauth:// URL with a TOTP secret.
 * The mobile app shows the same code; if this succeeds the client
 * can generate the OTP itself instead of asking you to type it. */
int feilian_get_otp_uri(feilian_client *c, char *body, size_t cap);

/* Generate a 6-digit TOTP (RFC 6238, SHA-1, 30 s step) from a base32
 * secret, using local time + c->date_offset_sec. Returns 0 on success. */
int feilian_totp(feilian_client *c, const char *secret, char *out6);

/* MFA at login (3.2 API, from app.asar):
 *  POST /api/v1/login/mfa/send   {mfa_type, login_scene:"login", account}
 *  POST /api/v1/login/mfa/verify {mfa_type, login_scene:"login", account, code}
 *  GET  /api/mfa/type — lists the MFA types the server offers
 *       (otp / email / mobile / password / passkey / push-app). */
int feilian_mfa_send(feilian_client *c, const char *mfa_type,
                     char *body, size_t cap);
int feilian_mfa_verify(feilian_client *c, const char *mfa_type,
                       const char *code, char *body, size_t cap);
int feilian_mfa_type(feilian_client *c, char *body, size_t cap);

/* Curve25519 WireGuard keypair, clamped as WireGuard requires.
 * private_b64 / public_b64 are base64, 44 chars + NUL. */
int feilian_gen_wg_keypair(char *private_b64, size_t priv_cap,
                           char *public_b64, size_t pub_cap);

/* Write a wg-quick style config. Returns 0 on success. */
int feilian_write_wg_conf(const char *path, const char *address,
                          const char *private_key, const char *peer_key,
                          const char *endpoint, const char *dns,
                          int mtu);

/* Minimal JSON helpers (no JSON library, to keep this dependency-free). */
int feilian_json_code(const char *body); /* "code": N, or -1 */
int feilian_json_string(const char *body, const char *key,
                        char *out, size_t cap);

void feilian_sha256_hex(const char *input, char *out_hex); /* 64 hex + NUL */

#endif
