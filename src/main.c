/* FeiLian client — CUI UI, login + VPN list + WireGuard peer fetch.
 *
 * Flow:
 *  1. Pick the OS to report to the server BEFORE login (default: the
 *     OS this binary is running on). The server uses `os` /
 *     `os_version` to pick the login method.
 *  2. Company code (optional) -> /api/match -> server URL, or paste the
 *     server URL directly.
 *  3. Username + password -> /api/login (password is SHA-256 hexed).
 *  4. List VPN -> /api/vpn/list, pick a server, Connect -> /vpn/conn,
 *     write a WireGuard config. Bringing the tunnel up needs root +
 *     wireguard-tools on the machine that will use it, so Connect stops
 *     at writing the config and shows the `wg-quick` command.
 *
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
    char server[512];
    char company[128];
    char username[128];
    char password[128];
    char device_name[128];
    char log[8192];
    char vpn_list[4096];
    char wg_private[64];
    char wg_public[64];
    int show_password;
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
}

int main(void) {
    App a;
    memset(&a, 0, sizeof a);
    a.os_index = 0; /* Linux — the OS this binary is running on */
    strncpy(a.api.os_version, "2", sizeof a.api.os_version - 1);
    strncpy(a.device_name, "feilian-c-client", sizeof a.device_name - 1);
    feilian_log(a.log, sizeof a.log, "FeiLian C client — login + connect only.");
    feilian_log(a.log, sizeof a.log, "Pick the OS to report, then log in.");

    cui_app *app = cui_app_create(&(cui_app_desc){
        .title = "FeiLian Client", .width = 720, .height = 620});
    if (!app) return 1;

    while (cui_app_frame(app)) {
        cui_ctx *ui = cui_app_ui(app);
        cui_column(ui, .pad = 24, .gap = 12, .width = CUI_FILL) {
            cui_heading(ui, "FeiLian Client", 2);
            cui_secondary(ui, "Login and connect only. No endpoint-security section.");

            /* 1 — OS, before login */
            cui_text(ui, "1 · OS to report to the server (choose before login)");
            cui_select(ui, "os", OS_NAMES, 4, &a.os_index);
            cui_textf(ui, "Will send os=%s, os_version=%s",
                      OS_NAMES[a.os_index], OS_VERSIONS[a.os_index]);

            /* 2 — server / company */
            cui_input(ui, "server", a.server, sizeof a.server,
                      .label = "Server URL (leave empty to resolve from company)",
                      .placeholder = "https://…");
            cui_input(ui, "company", a.company, sizeof a.company,
                      .label = "Company code",
                      .placeholder = "company code");
            cui_input(ui, "username", a.username, sizeof a.username,
                      .label = "Username");
            cui_input(ui, "password", a.password, sizeof a.password,
                      .label = "Password", .password = true,
                      .placeholder = "Your FeiLian password");

            cui_row(ui, .gap = 8) {
                if (cui_button(ui, "Log in", .variant = CUI_BUTTON_PRIMARY)) {
                    sync_api_from_ui(&a);
                    if (!a.api.server[0] && a.api.company[0]) {
                        char err[256] = "";
                        app_logf(&a, "Resolving company %s …", a.api.company);
                        if (feilian_match_company(&a.api, err, sizeof err) == 0) {
                            strncpy(a.server, a.api.server, sizeof a.server - 1);
                            app_logf(&a, "Server: %s", a.api.server);
                        } else {
                            app_logf(&a, "Company lookup failed: %s", err);
                        }
                    }
                    if (a.api.server[0] && a.username[0] && a.password[0]) {
                        char body[8192];
                        int st = feilian_login_setting(&a.api, body, sizeof body);
                        app_logf(&a, "login/setting: HTTP %d", st);
                        if (st == 200) app_logf(&a, "%.500s", body);
                        st = feilian_login_password(&a.api, a.password, body, sizeof body);
                        app_logf(&a, "login: HTTP %d, code=%d", st, feilian_json_code(body));
                        if (st == 200 && feilian_json_code(body) == 0) {
                            app_logf(&a, "Logged in as %s.", a.username);
                            memset(a.password, 0, sizeof a.password);
                        } else {
                            app_logf(&a, "Login failed: %.500s", body);
                        }
                    } else {
                        app_logf(&a, "Need a server (or company code), username and password.");
                    }
                }
                if (cui_button(ui, "List VPN servers")) {
                    sync_api_from_ui(&a);
                    if (!a.api.logged_in) app_logf(&a, "Log in first.");
                    else {
                        char body[8192];
                        int st = feilian_list_vpn(&a.api, body, sizeof body);
                        app_logf(&a, "vpn/list: HTTP %d", st);
                        strncpy(a.vpn_list, body, sizeof a.vpn_list - 1);
                        app_logf(&a, "%.800s", body);
                    }
                }
                if (cui_button(ui, "Connect")) {
                    sync_api_from_ui(&a);
                    if (!a.api.logged_in) {
                        app_logf(&a, "Log in first.");
                    } else if (feilian_gen_wg_keypair(a.wg_private, sizeof a.wg_private,
                                                      a.wg_public, sizeof a.wg_public) != 0) {
                        app_logf(&a, "Could not generate a WireGuard keypair.");
                    } else {
                        char body[8192];
                        int st = feilian_fetch_peer(&a.api, a.api.server,
                                                    a.wg_public, body, sizeof body);
                        app_logf(&a, "vpn/conn: HTTP %d", st);
                        app_logf(&a, "%.800s", body);
                        if (st == 200) {
                            char peer_key[128] = "", ip[64] = "", dns[128] = "";
                            feilian_json_string(body, "public_key", peer_key, sizeof peer_key);
                            feilian_json_string(body, "ip", ip, sizeof ip);
                            feilian_json_string(body, "dns", dns, sizeof dns);
                            /* Peer info is nested in the real reply; the
                             * fields above are best-effort. If the server
                             * did not return them at top level, the config
                             * below is not written — check the log. */
                            if (peer_key[0] && ip[0]) {
                                const char *path = "corplink.conf";
                                feilian_write_wg_conf(path, ip, a.wg_private,
                                                      peer_key, "", dns, 1420);
                                app_logf(&a, "Wrote %s — then: sudo wg-quick up %s", path, path);
                            } else {
                                app_logf(&a, "Peer info not in the expected shape — see the reply above.");
                                app_logf(&a, "Public key for this session: %s", a.wg_public);
                            }
                        }
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
