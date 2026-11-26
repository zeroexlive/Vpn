#ifndef FEILIAN_H
#define FEILIAN_H

#include <stddef.h>

/* FeiLian / CorpLink login + VPN list + WireGuard peer flow.
 *
 * Endpoints confirmed three ways:
 *  - strings in the official 3.2.16 Linux .deb (Electron UI + corplink-service):
 *    /api/v1/login, /api/login/setting, /api/vpn/list, /api/matchinternal
 *  - the public corplink-go / corplink-rs clients, which implement the same
 *    flow: https://github.com/kongfei605/corplink-go (api.go / client.go)
 *  - the official 3.2.16 Android APK (jadx decompile of classes2.dex):
 *    com.bytedance.topgo.base.vpn.VpnConfigModel posts the WireGuard
 *    config to https://<ip>:<api_port>/vpn/conn (bare path, no query)
 *    with {"mode":"Split","public_key":…,"otp":…,"export_id":0,
 *    "sign_token":"…","not_auto":true}, and the reply's data holds
 *    {ip, ipv6, ip_mask, public_key (base64), preshared_key (base64),
 *    sign_token, setting:{vpn_mtu, vpn_dns, …}}. The node request goes
 *    through OkHttp with CookieJarImpl(true, true) + HttpHeaderInterceptor:
 *    portal cookies are forwarded to the node despite the domain
 *    mismatch, AND the app synthesises device_id (= android_id) and
 *    device_name (= bluetooth name) cookies for the node host, plus a
 *    csrf-token header. Without the device cookies the node answers
 *    10220001 "Cookies are missing". This client mirrors that: the
 *    device id comes from /etc/machine-id (like the desktop service's
 *    device.conf) or a generated UUID, device_name is the hostname.
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

#define FEILIAN_MATCH_URL "https://corplink.isealsuite.com/api/match?language=en"
#define FEILIAN_MATCH_URL_LEGACY "https://corplink.volcengine.cn/api/match"
/* Same UA as the public corplink-go client — the server/WAF accepts it. */
#define FEILIAN_USER_AGENT "CorpLink/201000 (GooglePixel; Android 10; en)"

typedef struct {
    char server[512];      /* e.g. https://xxx.feilian.volcengine.cn, from /api/match */
    char company[128];     /* company code, used only for /api/match */
    char username[128];
    char os[32];           /* "Linux" | "Windows" | "Mac" | "Android" */
    char os_version[32];   /* e.g. "2" (corplink-go) — keep as the server expects */
    char device_name[128];
    char device_id[64];    /* stable per-machine id, like the desktop service's
                              device.conf / Android's android_id. Sent as a
                              device_id cookie on gateway-node requests. */
    int device_cookies_on; /* append device_id/device_name cookies (node only) */
    char cookies[4096];    /* Cookie: header value, accumulated from Set-Cookie */
    char totp_secret[128]; /* base32 TOTP secret from /api/v2/p/otp, if any */
    long date_offset_sec;  /* server Date minus local time, for TOTP */
    int last_ping_status;  /* HTTP status of the last GET <node>/vpn/ping */
    char last_ping_body[512]; /* first bytes of that ping reply (may carry
                                 a node session cookie or an error) */
    char last_error[512];  /* set by feilian_https on transport failure */
    int enable_self_signed; /* from /api/match: server uses a self-signed cert */
    char self_signed_cert[8192]; /* PEM from /api/match, if any */
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

/* GET /api/login/setting — shows which login methods the server offers.
 * 3.2.16: no query params. */
int feilian_login_setting(feilian_client *c, char *body, size_t cap);

/* POST /api/v1/login — 3.2.16 official flow:
 * {"login_scene":"feilian","account_type":"email",
 *  "account":"<email>","password":"<aesEncryptIv(password)>"}
 * The encryption is the SealSuite portal's aesEncrypt (see
 * feilian_aes_encrypt_password in feilian.c): fixed key/IV
 * derived from Number.MAX_SAFE_INTEGER, AES-256-CBC, hex.
 * Verified against the user's server — plain is rejected
 * with 40000, this is accepted as a parameter. */
int feilian_login_password(feilian_client *c, const char *password,
                           char *body, size_t cap);

/* AES-encrypt a password the way the portal / official client
 * does (aesEncrypt / aesEncryptIv). Returns 0 on success,
 * out_hex is lowercase hex, no IV prepended. */
int feilian_aes_encrypt_password(const char *password, char *out_hex, size_t cap);

/* Read data.next.action from the double-envelope login reply
 * (outer code, inner data is a JSON string). Returns 0 on success. */
int feilian_next_action(const char *body, char *out, size_t cap);

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

/* VPN-connect MFA (3.2.16 desktop store): verify the OTP FIRST,
 * then connect. POST /api/mfa/code/verify
 * {"mfa_scene":"vpn","code":"…","code_type":"otp"}.
 * POST /api/mfa/code/send {"mfa_scene":"vpn","code_type":"…"}
 * is the send for email/mobile (and the push probe). */
int feilian_vpn_mfa_verify(feilian_client *c, const char *code,
                           const char *code_type, char *body, size_t cap);
int feilian_vpn_mfa_send(feilian_client *c, const char *code_type,
                         char *body, size_t cap);

/* Does the jar hold a cookie with this name? (For log lines only.) */
int feilian_has_cookie(feilian_client *c, const char *name);

/* Log the NAMES of the cookies held (never their values). Useful
 * when a server says "cookies are missing" — it shows whether the
 * jar is empty or a cookie was rotated away. */
void feilian_log_cookie_names(feilian_client *c, char *log, size_t cap);

/* Saved login session — cookies only, never the password.
 * File: $HOME/.config/feilian-client/session, mode 0600.
 * Returns 0 on success. Load returns -1 when there is no usable
 * saved session; a loaded session must still be validated by the
 * caller (server answers code 101 when it has expired). */
int feilian_save_session(feilian_client *c);
int feilian_load_session(feilian_client *c);
int feilian_clear_session(void);

/* TOTP secret for generating the Connect OTP locally (RFC 6238,
 * same as the mobile app's authenticator: base32 secret, HMAC-SHA1,
 * 6 digits, 30 s window). Stored in
 * ~/.config/feilian-client/totp_secret, mode 0600 — the secret is
 * as sensitive as a password and is never logged or sent anywhere;
 * only the generated 6-digit code goes to the server. The secret
 * comes from the deployment's authenticator setup (portal security
 * settings / QR code's secret= parameter); there is no API to fetch
 * an already-bound secret, and 3.2.16 has no /api/v2/p/otp. */
int feilian_save_totp_secret(const char *secret);
int feilian_load_totp_secret(char *out, size_t cap);
int feilian_clear_totp_secret(void);
int feilian_gen_wg_keypair(char *private_b64, size_t priv_cap,
                           char *public_b64, size_t pub_cap);

/* Write a wg-quick style config. Returns 0 on success.
 * preshared may be "" (omitted); endpoint is "ip:vpn_port". */
int feilian_write_wg_conf(const char *path, const char *address,
                          const char *private_key, const char *peer_key,
                          const char *preshared, const char *endpoint,
                          const char *dns, int mtu);

/* Minimal JSON helpers (no JSON library, to keep this dependency-free). */
int feilian_json_code(const char *body); /* "code": N, or -1 */
int feilian_json_int(const char *body, const char *key); /* "key": N, or -1 */
int feilian_json_string(const char *body, const char *key,
                        char *out, size_t cap);

/* Stable per-machine device id (desktop service's device.conf /
 * Android's android_id equivalent): /etc/machine-id when readable,
 * else a UUIDv4 generated once and kept in
 * $HOME/.config/feilian-client/device_id (0600). Cached in
 * c->device_id. Returns 0 on success. */
int feilian_ensure_device_id(feilian_client *c);

void feilian_sha256_hex(const char *input, char *out_hex); /* 64 hex + NUL */

#endif
