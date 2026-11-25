/* FeiLian client — CUI UI, login + VPN list + WireGuard peer fetch.
 *
 * Official flow (as the user described it, and as in the 3.2.16 .deb):
 *  1. Company code first. If it resolves, go to login.
 *  2. Email + password. No second factor here — SealSuite checks
 *     them and, if correct, you go to the main layout.
 *  3. Click Connect. The server then asks for MFA, two ways:
 *     a. Enter the 6-digit OTP code from the mobile app
 *        (TOTP, shown in the mobile app as e.g. "617 928"), or
 *     b. Confirm on the mobile app (push authentication).
 *     Way (a) is sent as {"public_key": ..., "otp": "617928"} to
 *     POST /vpn/conn. Way (b) in the official client goes through
 *     corplink-service sendPushConfirm {scene:"vpn"}; this client
 *     tries the server's MFA push endpoint and, if the server does
 *     not offer one, tells you to use (a). After login the client
 *     also tries GET /api/v2/p/otp — if the server returns an
 *     otpauth:// URL with a TOTP secret, the OTP is generated
 *     locally and the code field is filled in for you.
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

#include "feilian.h"

static const char *OS_NAMES[] = {"Linux", "Windows", "Mac", "Android"};
static const char *OS_VERSIONS[] = {"2", "2", "2", "2"};

typedef struct {
    feilian_client api;
    int os_index;
    int stage; /* 0 company, 1 email/password, 2 main layout */
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

/* After a successful password login, try to fetch the TOTP secret so
 * Connect can fill the OTP in by itself. */
static void try_fetch_totp_secret(App *a) {
    char body[8192];
    int st = feilian_get_otp_uri(&a->api, body, sizeof body);
    if (st != 200) { app_logf(a, "otp uri: HTTP %d (OTP will be manual)", st); return; }
    char url[1024] = "";
    if (feilian_json_string(body, "url", url, sizeof url) < 0) {
        app_logf(a, "otp uri: no url in reply (OTP will be manual)");
        return;
    }
    const char *s = strstr(url, "secret=");
    if (!s) { app_logf(a, "otp uri: no secret in %s", url); return; }
    s += strlen("secret=");
    size_t i = 0;
    while (s[i] && s[i] != '&' && i + 1 < sizeof a->api.totp_secret)
        a->api.totp_secret[i] = s[i], i++;
    a->api.totp_secret[i] = '\0';
    app_logf(a, "TOTP secret saved — Connect will generate the OTP itself.");
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
    int st = feilian_fetch_peer_otp(&a->api, a->api.server, a->wg_public, otp, body, sizeof body);
    app_logf(a, "vpn/conn: HTTP %d", st);
    app_logf(a, "%.800s", body);
    if (st == 200 && feilian_json_code(body) == 0) {
        char peer_key[128] = "", ip[64] = "", dns[128] = "";
        feilian_json_string(body, "public_key", peer_key, sizeof peer_key);
        feilian_json_string(body, "ip", ip, sizeof ip);
        feilian_json_string(body, "dns", dns, sizeof dns);
        if (peer_key[0] && ip[0]) {
            const char *path = "corplink.conf";
            feilian_write_wg_conf(path, ip, a->wg_private, peer_key, "", dns, 1420);
            app_logf(a, "Connected — wrote %s, then: sudo wg-quick up %s", path, path);
        } else {
            app_logf(a, "Peer info not in the expected shape — see the reply above.");
            app_logf(a, "Public key for this session: %s", a->wg_public);
        }
    } else {
        app_logf(a, "Connect failed — check the OTP (it changes every 30 s) and try again.");
    }
}

int main(void) {
    App a;
    memset(&a, 0, sizeof a);
    a.os_index = 0; /* Linux — the OS this binary is running on */
    strncpy(a.api.os_version, "2", sizeof a.api.os_version - 1);
    strncpy(a.device_name, "feilian-c-client", sizeof a.device_name - 1);
    feilian_log(a.log, sizeof a.log, "FeiLian C client — login + connect only.");
    feilian_log(a.log, sizeof a.log, "Step 1: pick the OS, enter the company code.");

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
                            if (st == 200 && feilian_json_code(body) == 0) {
                                app_logf(&a, "Logged in as %s.", a.username);
                                a.api.logged_in = 1;
                                memset(a.password, 0, sizeof a.password);
                                try_fetch_totp_secret(&a);
                                a.stage = 2;
                            } else {
                                app_logf(&a, "Login failed: %.500s", body);
                                app_logf(&a, "Check email / password and try again. There is no second factor at login — MFA is only at Connect.");
                            }
                        } else {
                            app_logf(&a, "Need a server, email and password.");
                        }
                    }
                    if (cui_button(ui, "Back")) a.stage = 0;
                }
            } else {
                cui_textf(ui, "Hi, %s", a.username);
                cui_textf(ui, "VPN Network · Server: %s", a.server);
                cui_text(ui, "Step 3 · Connect — the server will ask for MFA");
                cui_input(ui, "otp", a.otp, sizeof a.otp,
                          .label = "One-Time Password",
                          .placeholder = "6-digit code from your mobile app (e.g. 617928)");
                cui_text(ui, "Leave the code empty if the TOTP secret was fetched — it will be generated for you.");
                cui_row(ui, .gap = 8) {
                    if (cui_button(ui, "Connect", .variant = CUI_BUTTON_PRIMARY)) do_connect(&a);
                    if (cui_button(ui, "Confirm on mobile app")) {
                        sync_api_from_ui(&a);
                        char body[8192];
                        int st = feilian_mfa_type(&a.api, body, sizeof body);
                        app_logf(&a, "mfa/type: HTTP %d — %.500s", st, body);
                        if (st == 200 && strstr(body, "push")) {
                            st = feilian_mfa_send(&a.api, "push", body, sizeof body);
                            app_logf(&a, "Push sent to your mobile app (mfa/send push): HTTP %d — %.500s", st, body);
                            app_logf(&a, "Approve it on your mobile app, then press Connect.");
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
                    }
                    if (cui_button(ui, "Log out")) {
                        a.stage = 0; a.api.logged_in = 0;
                        memset(a.password, 0, sizeof a.password);
                        memset(a.otp, 0, sizeof a.otp);
                        app_logf(&a, "Logged out.");
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
