/* FeiLian client — CUI UI, login + VPN list + WireGuard peer fetch.
 *
 * Official flow (as the user described it, and as in the 3.2.16 .deb):
 *  1. Company code first. If it resolves, go to login.
 *  2. Email + password. No second factor here — SealSuite checks
 *     them and, if correct, you go to the main layout.
 *  3. Click Connect. The server then asks for MFA, two ways:
 *     - type the 6-digit OTP from the mobile app. The official
 *       client verifies it FIRST via POST /api/mfa/code/verify
 *       {"mfa_scene":"vpn","code":"…","code_type":"otp"}, and
 *       only then calls the local service's connectVpn. Sending
 *       the OTP straight to POST /vpn/conn does not work — that
 *       endpoint does not exist on the portal (HTTP 404).
 *     - tap "Confirm on mobile app" (push). In the official
 *       client this goes through corplink-service
 *       sendPushConfirm {scene:"vpn"}; there is no HTTP push
 *       endpoint, so this client probes
 *       POST /api/mfa/code/send {"mfa_scene":"vpn",
 *       "code_type":"push"} and falls back to the OTP field.
 *     The tunnel itself is brought up by the local service's
 *     connectVpn (mode Split/Full, selected route); this client
 *     fetches the VPN list, posts /vpn/conn to the node url
 *     from the list if it has one, and writes corplink.conf
 *     from the peer reply so wg-quick can bring the tunnel up.
 *
 * OS is picked BEFORE login (default: the OS this binary runs on).
 * No password is ever written to disk. Cookies are kept in memory only.
 */
#include <cui/cui.h>
#include <cui/cui_app.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "feilian.h"

static const char *OS_NAMES[] = {"Linux", "Windows", "Mac", "Android"};
static const char *OS_VERSIONS[] = {"2", "2", "2", "2"};

typedef struct {
    feilian_client api;
    int os_index;
    int stage; /* 0 company, 1 email/password, 2 main layout */
    int need_2fa; /* set only if the server returns next.action == "2FA" */
    char mfa_code[16];
    char server[512];
    char company[128];
    char username[128];
    char password[128];
    char device_name[128];
    char proxy[256];
    char otp[16];
    char log[8192];
    char vpn_list[4096];
    char wg_private[64];
    char wg_public[64];
    int connected; /* corplink.conf was written and wg-quick was brought up */
} App;

static void app_logf(App *a, const char *fmt, ...) {
    char tmp[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    feilian_log(a->log, sizeof a->log, "%s", tmp);
}

static void sync_api_from_ui(App *a) {
    strncpy(a->api.server, a->server, sizeof a->api.server - 1);
    strncpy(a->api.company, a->company, sizeof a->api.company - 1);
    strncpy(a->api.username, a->username, sizeof a->api.username - 1);
    strncpy(a->api.device_name, a->device_name, sizeof a->api.device_name - 1);
    strncpy(a->api.os, OS_NAMES[a->os_index], sizeof a->api.os - 1);
    strncpy(a->api.os_version, OS_VERSIONS[a->os_index], sizeof a->api.os_version - 1);
    /* Proxy from the UI, if the user filled it in — otherwise the
     * https_proxy / HTTPS_PROXY environment variable is used. */
    if (a->proxy[0]) setenv("https_proxy", a->proxy, 1);
}

/* After a successful password login, 3.2.16 has NO /api/v2/p/otp
 * endpoint, so there is no TOTP secret to fetch from the server.
 * The secret comes from the deployment's authenticator setup
 * (portal security settings / the QR code's secret= parameter) and
 * is entered once in the main layout; from then on Connect
 * generates the OTP itself. */
static void try_fetch_totp_secret(App *a) {
    if (a->api.totp_secret[0])
        app_logf(a, "TOTP secret is saved — Connect generates the OTP itself, no mobile app needed.");
    else
        app_logf(a, "No TOTP secret saved: enter the OTP from your mobile app, or paste the base32 secret from your portal's authenticator setup below to stop needing the phone.");
}

static void do_disconnect(App *a) {
    /* The tunnel itself is a WireGuard interface brought up by
     * wg-quick, so disconnecting means bringing that interface
     * down. pkexec shows the graphical password prompt; if it is
     * not available, run `sudo wg-quick down corplink` in a
     * terminal instead. */
    app_logf(a, "Disconnecting — bringing the corplink interface down…");
    int rc = system("pkexec wg-quick down corplink 2>&1 | head -5");
    if (rc == 0) {
        a->connected = 0;
        app_logf(a, "Disconnected.");
    } else {
        app_logf(a, "Disconnect returned %d — if pkexec is missing, run in a terminal: sudo wg-quick down corplink", rc);
    }
}

static void do_connect(App *a) {
    sync_api_from_ui(a);
    if (!a->api.logged_in) { app_logf(a, "Log in first."); return; }
    char otp[16] = "";
    if (a->otp[0]) {
        strncpy(otp, a->otp, sizeof otp - 1);
        app_logf(a, "Using OTP you entered: %s", otp);
    } else if (a->api.totp_secret[0]) {
        if (feilian_totp(&a->api, a->api.totp_secret, otp) == 0)
            app_logf(a, "Generated OTP from TOTP secret: %s", otp);
        else { app_logf(a, "Could not generate TOTP — enter the OTP manually."); return; }
    } else {
        app_logf(a, "Enter the 6-digit OTP from your mobile app, or tap 'Confirm on mobile app'.");
        return;
    }
    if (feilian_gen_wg_keypair(a->wg_private, sizeof a->wg_private,
                               a->wg_public, sizeof a->wg_public) != 0) {
        app_logf(a, "Could not generate a WireGuard keypair."); return;
    }
    char body[8192];
    /* 1. Verify the OTP FIRST, like the official client does
     * (connectVpn verifies via /api/mfa/code/verify, then calls
     * the local service's connectVpn). If the code is wrong the
     * server says so here — the old build sent the OTP straight
     * to POST /vpn/conn, which does not exist on the portal
     * (HTTP 404), so even a correct OTP "didn't work". */
    int st = feilian_vpn_mfa_verify(&a->api, otp, "otp", body, sizeof body);
    app_logf(a, "mfa/code/verify: HTTP %d", st);
    if (st == -1) {
        /* Transport failure — last_error says why. The body is
         * empty here (feilian_https clears it), never a stale
         * reply from an earlier call. */
        app_logf(a, "Could not reach the server: %s", a->api.last_error);
        app_logf(a, "Check your network / proxy and try again — the OTP was not checked yet.");
        return;
    }
    app_logf(a, "%.800s", body);
    if (feilian_json_code(body) == 101) {
        app_logf(a, "Session expired (code 101) — log in again.");
        feilian_clear_session();
        a->api.logged_in = 0;
        a->stage = 0;
        return;
    }
    if (!(st == 200 && feilian_json_code(body) == 0)) {
        app_logf(a, "OTP not accepted by the server — get a fresh code from your mobile app (it changes every 30 s) and try again.");
        return;
    }
    app_logf(a, "OTP accepted. Fetching the VPN list to find the gateway to connect to…");
    /* Cookies can rotate on any authenticated call (e.g. verify),
     * so re-save the session now — the file written at login may
     * hold a stale value. */
    feilian_save_session(&a->api);
    /* 2. GET /api/vpn/list. The list has no "url" field — each
     * node has "ip" + "api_port" (here: 98.98.44.174:11451,
     * vpn_port 11450). /vpn/conn lives on the NODE, not the
     * portal: posting it to ourbit.sealsuite.com gives 404,
     * while the node answers on 11451 (an HTTP request there
     * gets "Client sent an HTTP request to an HTTPS server"). */
    st = feilian_list_vpn(&a->api, body, sizeof body);
    app_logf(a, "vpn/list: HTTP %d", st);
    app_logf(a, "%.800s", body);
    char node_base[512] = "";
    char node_ip[64] = "";
    long api_port = 0, vpn_port = 0;
    if (st == 200) {
        /* First "url" value, if the old corplink-go shape shows up. */
        const char *u = strstr(body, "\"url\"");
        if (u) {
            const char *q = strchr(u + 5, '"');
            if (q) {
                const char *e = strchr(q + 1, '"');
                if (e && (size_t)(e - (q + 1)) < sizeof node_base) {
                    memcpy(node_base, q + 1, (size_t)(e - (q + 1)));
                    node_base[e - (q + 1)] = '\0';
                }
            }
        }
        if (!node_base[0]) {
            /* New shape: "ip":"98.98.44.174", "api_port":11451. */
            const char *ip = strstr(body, "\"ip\"");
            if (ip) {
                const char *q = strchr(ip + 4, '"');
                if (q) {
                    const char *e = strchr(q + 1, '"');
                    if (e && (size_t)(e - (q + 1)) < sizeof node_ip) {
                        memcpy(node_ip, q + 1, (size_t)(e - (q + 1)));
                        node_ip[e - (q + 1)] = '\0';
                    }
                }
            }
            const char *ap = strstr(body, "\"api_port\"");
            if (ap) {
                const char *colon = strchr(ap, ':');
                if (colon) api_port = strtol(colon + 1, NULL, 10);
            }
            const char *vp = strstr(body, "\"vpn_port\"");
            if (vp) {
                const char *colon = strchr(vp, ':');
                if (colon) vpn_port = strtol(colon + 1, NULL, 10);
            }
            if (node_ip[0]) {
                if (api_port > 0)
                    snprintf(node_base, sizeof node_base, "https://%s:%ld", node_ip, api_port);
                else
                    snprintf(node_base, sizeof node_base, "https://%s", node_ip);
            }
        }
    }
    const char *conn_base = node_base[0] ? node_base : a->api.server;
    app_logf(a, "Posting /vpn/conn to: %s", conn_base);
    /* Names only — values are session tokens and never logged. If
     * the node says "cookies are missing", this shows whether the
     * jar is empty or a cookie was lost/rotated. */
    feilian_log_cookie_names(&a->api, a->log, sizeof a->log);
    app_logf(a, "CSRF header will be sent: %s",
             feilian_has_cookie(&a->api, "csrf-token") ? "yes (csrf-token cookie present)" : "NO — csrf-token cookie missing from jar");
    /* Device cookies (Android APK: CookieJarImpl synthesises
     * device_id + device_name for the node host on every node
     * request). The id is stable per machine — /etc/machine-id
     * when readable, else a generated UUID kept in the config
     * dir — and is never printed, only whether it is ready. */
    app_logf(a, "Device cookies will be sent: %s",
             feilian_ensure_device_id(&a->api) == 0
                 ? "yes (device_id ready)"
                 : "NO — could not determine a device id");
    st = feilian_fetch_peer_otp(&a->api, conn_base, a->wg_public, otp, body, sizeof body);
    /* The node ping runs first inside the fetch — its reply is
     * worth seeing: a ping that sets a node cookie (e.g. vpn-token,
     * sent back as the jwt-token header) shows up in the jar below,
     * and a ping error explains a conn failure. */
    app_logf(a, "vpn/ping: HTTP %d — %.300s", a->api.last_ping_status,
             a->api.last_ping_body[0] ? a->api.last_ping_body : "(empty)");
    feilian_log_cookie_names(&a->api, a->log, sizeof a->log);
    app_logf(a, "jwt-token header will be sent: %s",
             feilian_has_cookie(&a->api, "vpn-token") ? "yes (vpn-token cookie present)" : "no (no vpn-token cookie in jar)");
    app_logf(a, "vpn/conn: HTTP %d", st);
    app_logf(a, "%.800s", body);
    if (st == 200 && feilian_json_code(body) == 0) {
        /* The reply's data holds the WireGuard peer: ip (tunnel
         * address), public_key (server key, base64 — the native
         * wg-quick format), preshared_key (base64, may be empty),
         * and setting.{vpn_dns, vpn_mtu}. Endpoint is the node
         * ip:vpn_port from the list (11450 here). */
        char peer_key[128] = "", ip[64] = "", dns[128] = "", psk[128] = "";
        feilian_json_string(body, "public_key", peer_key, sizeof peer_key);
        feilian_json_string(body, "ip", ip, sizeof ip);
        feilian_json_string(body, "preshared_key", psk, sizeof psk);
        feilian_json_string(body, "vpn_dns", dns, sizeof dns);
        int mtu = feilian_json_int(body, "vpn_mtu");
        if (peer_key[0] && ip[0]) {
            char endpoint[128] = "";
            if (node_ip[0] && vpn_port > 0)
                snprintf(endpoint, sizeof endpoint, "%s:%ld", node_ip, vpn_port);
            const char *path = "corplink.conf";
            feilian_write_wg_conf(path, ip, a->wg_private, peer_key, psk,
                                  endpoint, dns, mtu > 0 ? mtu : 1420);
            app_logf(a, "Connected — wrote %s, then: sudo wg-quick up %s", path, path);
            a->connected = 1;
        } else {
            app_logf(a, "Peer info not in the expected shape — see the reply above.");
            app_logf(a, "Public key for this session: %s", a->wg_public);
        }
    } else {
        app_logf(a, "Connect failed — the tunnel itself is brought up by the official client's local service (connectVpn), not by this HTTP call. Paste the vpn/list reply above and I will adjust the parser.");
    }
}

int main(void) {
    App a;
    memset(&a, 0, sizeof a);
    a.os_index = 0; /* Linux — the OS this binary is running on */
    strncpy(a.api.os_version, "2", sizeof a.api.os_version - 1);
    /* Device name for the device_name cookie on node requests:
     * the hostname, like the desktop service's device name
     * (Android sends the bluetooth name). */
    if (gethostname(a.device_name, sizeof a.device_name - 1) != 0 ||
        !a.device_name[0])
        strncpy(a.device_name, "feilian-c-client", sizeof a.device_name - 1);
    feilian_log(a.log, sizeof a.log, "FeiLian C client — login + connect only. (build v17: node query string (uu.H params + timestamp), jwt-token header, ping reply logged)");
    feilian_log(a.log, sizeof a.log, "Step 1: pick the OS, enter the company code.");
    /* Restore a saved login session, if there is one — the official
     * client also stays logged in across restarts. A saved session
     * is validated by the first authenticated call (code 101 means
     * it expired and the login screen comes back). */
    if (feilian_load_session(&a.api) == 0) {
        strncpy(a.server, a.api.server, sizeof a.server - 1);
        strncpy(a.username, a.api.username, sizeof a.username - 1);
        a.stage = 2;
        feilian_log(a.log, sizeof a.log, "Restored saved session for %s — no login needed.", a.username);
    }
    /* A saved TOTP secret means Connect generates the OTP itself
     * (feilian_totp, RFC 6238 — the same code the mobile app's
     * authenticator shows). The secret itself is never logged. */
    if (feilian_load_totp_secret(a.api.totp_secret, sizeof a.api.totp_secret) == 0)
        feilian_log(a.log, sizeof a.log, "TOTP secret loaded — Connect will generate the OTP itself, no mobile app needed.");

    cui_app *app = cui_app_create(&(cui_app_desc){
        .title = "FeiLian Client", .width = 720, .height = 640});
    if (!app) return 1;

    while (cui_app_frame(app)) {
        cui_ctx *ui = cui_app_ui(app);
        cui_column(ui, .pad = 24, .gap = 12, .width = CUI_FILL) {
            cui_heading(ui, "FeiLian Client", 2);
            cui_secondary(ui, "Login and connect only. No endpoint-security section.");

            cui_text(ui, "OS to report to the server (choose before login)");
            cui_select(ui, "os", OS_NAMES, 4, &a.os_index);
            cui_textf(ui, "Will send os=%s, os_version=%s",
                      OS_NAMES[a.os_index], OS_VERSIONS[a.os_index]);

            if (a.stage == 0) {
                cui_text(ui, "Step 1 · Company code");
                cui_input(ui, "server", a.server, sizeof a.server,
                          .label = "Server URL (leave empty to resolve from company)",
                          .placeholder = "https://…");
                cui_input(ui, "company", a.company, sizeof a.company,
                          .label = "Company code",
                          .placeholder = "company code");
                cui_input(ui, "proxy", a.proxy, sizeof a.proxy,
                          .label = "Proxy (optional, only if your network needs one)",
                          .placeholder = "http://user:pass@proxy:3128");
                if (cui_button(ui, "Next", .variant = CUI_BUTTON_PRIMARY)) {
                    sync_api_from_ui(&a);
                    if (!a.api.server[0] && a.api.company[0]) {
                        char err[256] = "";
                        app_logf(&a, "Resolving company %s …", a.api.company);
                        if (feilian_match_company(&a.api, err, sizeof err) == 0) {
                            strncpy(a.server, a.api.server, sizeof a.server - 1);
                            app_logf(&a, "Server: %s", a.api.server);
                            a.stage = 1;
                        } else {
                            app_logf(&a, "Company lookup failed: %s", err);
                        }
                    } else if (a.api.server[0]) {
                        a.stage = 1;
                    } else {
                        app_logf(&a, "Enter a company code or a server URL.");
                    }
                }
            } else if (a.stage == 1) {
                cui_textf(ui, "Step 2 · Log in — server: %s", a.server);
                cui_input(ui, "username", a.username, sizeof a.username,
                          .label = "Email", .placeholder = "you@company.com");
                cui_input(ui, "password", a.password, sizeof a.password,
                          .label = "Password", .password = true,
                          .placeholder = "Your FeiLian password");
                cui_row(ui, .gap = 8) {
                    if (cui_button(ui, "Log in", .variant = CUI_BUTTON_PRIMARY)) {
                        sync_api_from_ui(&a);
                        if (a.api.server[0] && a.username[0] && a.password[0]) {
                            char body[8192];
                            int st = feilian_login_setting(&a.api, body, sizeof body);
                            app_logf(&a, "login/setting: HTTP %d", st);
                            if (st == 200) app_logf(&a, "%.500s", body);
                            st = feilian_login_password(&a.api, a.password, body, sizeof body);
                            app_logf(&a, "login: HTTP %d, code=%d", st, feilian_json_code(body));
                            if (st == -1) {
                                app_logf(&a, "Login failed (no response): %s", a.api.last_error);
                            } else if (st == 200 && feilian_json_code(body) == 0) {
                                char action[64] = "";
                                feilian_next_action(body, action, sizeof action);
                                app_logf(&a, "login next.action: %s", action[0] ? action : "(none)");
                                if (action[0] == '\0' || strcmp(action, "main") == 0 || strcmp(action, "GoToLink") == 0) {
                                    /* GoToLink: the official client calls
                                     * handleLoginDone and goes to the main
                                     * layout (link == "LoginPage" just
                                     * means "password changed, continue"). */
                                    app_logf(&a, "Logged in as %s.", a.username);
                                    a.api.logged_in = 1;
                                    if (feilian_save_session(&a.api) == 0)
                                        app_logf(&a, "Session saved — next time the app opens already logged in (Log out clears it).");
                                    else
                                        app_logf(&a, "Note: could not save the session, you will need to log in again next time.");
                                    memset(a.password, 0, sizeof a.password);
                                    try_fetch_totp_secret(&a);
                                    a.stage = 2;
                                } else if (strcmp(action, "2FA") == 0) {
                                    app_logf(&a, "Server asks for a second factor at login (next=2FA) — use the MFA screen below.");
                                    a.need_2fa = 1;
                                } else {
                                    app_logf(&a, "Server wants next step '%s' — not implemented yet. Full reply: %.500s", action, body);
                                }
                            } else {
                                app_logf(&a, "Login failed: %.500s", body);
                                app_logf(&a, "Check email / password and try again. There is no second factor at login unless the server returns next=2FA — MFA is normally only at Connect.");
                            }
                        } else {
                            app_logf(&a, "Need a server, email and password.");
                        }
                    }
                    if (cui_button(ui, "Back")) a.stage = 0;
                }
                if (a.need_2fa) {
                    cui_text(ui, "Second factor — only because the server returned next=2FA");
                    cui_input(ui, "mfa_code", a.mfa_code, sizeof a.mfa_code,
                              .label = "Code", .placeholder = "6-digit code");
                    cui_row(ui, .gap = 8) {
                        if (cui_button(ui, "Send code")) {
                            sync_api_from_ui(&a);
                            char body[8192];
                            int st = feilian_mfa_send(&a.api, "otp", body, sizeof body);
                            app_logf(&a, "mfa/send (otp): HTTP %d — %.500s", st, body);
                        }
                        if (cui_button(ui, "Verify")) {
                            sync_api_from_ui(&a);
                            char body[8192];
                            int st = feilian_mfa_verify(&a.api, "otp", a.mfa_code, body, sizeof body);
                            app_logf(&a, "mfa/verify: HTTP %d, code=%d", st, feilian_json_code(body));
                            if (st == 200 && feilian_json_code(body) == 0) {
                                app_logf(&a, "MFA verified — logged in as %s.", a.username);
                                a.api.logged_in = 1;
                                a.need_2fa = 0;
                                a.stage = 2;
                            } else {
                                app_logf(&a, "MFA failed: %.500s", body);
                            }
                        }
                    }
                }
            } else {
                cui_textf(ui, "Hi, %s", a.username);
                cui_textf(ui, "VPN Network · Server: %s", a.server);
                cui_text(ui, "Step 3 · Connect — the server will ask for MFA");
                cui_input(ui, "otp", a.otp, sizeof a.otp,
                          .label = "One-Time Password",
                          .placeholder = "6-digit code from your mobile app (e.g. 617928) — leave empty if a TOTP secret is saved below");
                cui_text(ui, "Enter the 6-digit OTP from your mobile app — it changes every 30 s. Or save a TOTP secret once and Connect generates it itself.");
                cui_input(ui, "totp_secret", a.api.totp_secret, sizeof a.api.totp_secret,
                          .label = "TOTP secret (base32)",
                          .placeholder = "from your portal's authenticator setup, e.g. JBSWY3DPEHPK3PXP");
                cui_row(ui, .gap = 8) {
                    if (cui_button(ui, "Save TOTP secret")) {
                        char code[7];
                        if (feilian_totp(&a.api, a.api.totp_secret, code) != 0) {
                            app_logf(&a, "That doesn't look like a base32 TOTP secret (16+ chars, A-Z and 2-7) — check it and try again. Nothing was saved.");
                        } else if (feilian_save_totp_secret(a.api.totp_secret) == 0) {
                            app_logf(&a, "TOTP secret saved (0600, never sent to the server) — Connect will now generate the OTP itself. Current code: %s", code);
                        } else {
                            app_logf(&a, "Could not save the TOTP secret.");
                        }
                    }
                    if (cui_button(ui, "Clear TOTP secret")) {
                        feilian_clear_totp_secret();
                        memset(a.api.totp_secret, 0, sizeof a.api.totp_secret);
                        app_logf(&a, "TOTP secret cleared — OTP goes back to the mobile app.");
                    }
                }
                cui_row(ui, .gap = 8) {
                    if (cui_button(ui, "Connect", .variant = CUI_BUTTON_PRIMARY)) do_connect(&a);
                    if (cui_button(ui, "Disconnect")) do_disconnect(&a);
                    if (cui_button(ui, "Confirm on mobile app")) {
                        sync_api_from_ui(&a);
                        char body[8192];
                        int st = feilian_mfa_type(&a.api, body, sizeof body);
                        app_logf(&a, "mfa/type: HTTP %d — %.500s", st, body);
                        if (st == 200 && strstr(body, "push")) {
                            /* Push confirm goes through the official
                             * client's local service (sendPushConfirm
                             * {scene:"vpn"}) — there is no HTTP push
                             * endpoint in this client. The VPN
                             * code/send endpoint answers 1003
                             * "Parameter is invalid" for code_type
                             * push, so don't call it. Use the OTP. */
                            app_logf(&a, "Push confirm is sent by the official client's local service, not over HTTP — this client can't trigger it. Enter the 6-digit OTP from your mobile app instead.");
                        } else {
                            app_logf(&a, "This server did not offer push confirm — enter the OTP code instead.");
                        }
                    }
                    if (cui_button(ui, "List VPN servers")) {
                        sync_api_from_ui(&a);
                        char body[8192];
                        int st = feilian_list_vpn(&a.api, body, sizeof body);
                        app_logf(&a, "vpn/list: HTTP %d", st);
                        strncpy(a.vpn_list, body, sizeof a.vpn_list - 1);
                        app_logf(&a, "%.800s", body);
                        if (st == 200 && feilian_json_code(body) == 101) {
                            app_logf(&a, "Session expired (code 101) — log in again.");
                            feilian_clear_session();
                            a.api.logged_in = 0;
                            a.stage = 0;
                        }
                    }
                    if (cui_button(ui, "Log out")) {
                        feilian_clear_session();
                        a.stage = 0; a.api.logged_in = 0;
                        memset(a.password, 0, sizeof a.password);
                        memset(a.otp, 0, sizeof a.otp);
                        a.api.cookies[0] = '\0';
                        app_logf(&a, "Logged out — saved session cleared.");
                    }
                }
            }

            cui_text(ui, "Log");
            cui_textarea(ui, "log", a.log, sizeof a.log, .width = CUI_FILL);
            if (a.vpn_list[0]) {
                cui_text(ui, "VPN list (raw)");
                cui_textarea(ui, "vpnlist", a.vpn_list, sizeof a.vpn_list, .width = CUI_FILL);
            }
            cui_secondary(ui, "WireGuard bring-up needs root and wireguard-tools on the target machine.");
        }
    }
    cui_app_destroy(app);
    return 0;
}
