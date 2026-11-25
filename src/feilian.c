#define _GNU_SOURCE 1
#define _DEFAULT_SOURCE 1
#include "feilian.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

void feilian_log(char *log, size_t cap, const char *fmt, ...) {
    char tmp[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    size_t len = strlen(log);
    if (len + strlen(tmp) + 2 >= cap) return;
    strcat(log, tmp);
    strcat(log, "\n");
}

void feilian_sha256_hex(const char *input, char *out_hex) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)input, strlen(input), digest);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(out_hex + i * 2, "%02x", digest[i]);
    out_hex[64] = '\0';
}

int feilian_json_code(const char *body) {
    const char *p = strstr(body, "\"code\"");
    if (!p) return -1;
    p = strchr(p, ':');
    if (!p) return -1;
    return atoi(p + 1);
}

/* Find "key":"value" (first occurrence, top-level-ish). */
int feilian_json_string(const char *body, const char *key,
                        char *out, size_t cap) {
    char pat[128];
    snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *p = strstr(body, pat);
    if (!p) return -1;
    p = strchr(p + strlen(pat), ':');
    if (!p) return -1;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '"') return -1;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < cap) {
        if (*p == '\\' && p[1]) p++;
        out[i++] = *p++;
    }
    out[i] = '\0';
    return (int)i;
}

static void accumulate_cookies(feilian_client *c, const char *headers) {
    const char *p = headers;
    while ((p = strcasestr(p, "set-cookie:")) != NULL) {
        p += strlen("set-cookie:");
        while (*p == ' ') p++;
        const char *end = strchr(p, ';');
        if (!end) end = strchr(p, '\r');
        if (!end) end = p + strlen(p);
        char pair[512];
        size_t n = (size_t)(end - p);
        if (n >= sizeof pair) n = sizeof pair - 1;
        memcpy(pair, p, n);
        pair[n] = '\0';
        if (!strstr(c->cookies, pair)) {
            if (c->cookies[0]) strncat(c->cookies, "; ", sizeof c->cookies - strlen(c->cookies) - 1);
            strncat(c->cookies, pair, sizeof c->cookies - strlen(c->cookies) - 1);
        }
        p = end;
    }
}

/* Plain TCP connect, no TLS. Returns fd or -1. */
static int connect_host(const char *host, int port) {
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char port_s[16];
    snprintf(port_s, sizeof port_s, "%d", port);
    if (getaddrinfo(host, port_s, &hints, &res) != 0) return -1;
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -1; }
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd); freeaddrinfo(res); return -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* If https_proxy/HTTPS_PROXY is set, tunnel through it with CONNECT.
 * Returns a connected fd (to the target, via proxy) or -1. */
static int connect_via_proxy(const char *host, int port) {
    const char *proxy = getenv("https_proxy");
    if (!proxy || !proxy[0]) proxy = getenv("HTTPS_PROXY");
    if (!proxy || !proxy[0]) proxy = getenv("http_proxy");
    if (!proxy || !proxy[0]) proxy = getenv("HTTP_PROXY");
    if (!proxy || !proxy[0]) return -1;
    if (strncmp(proxy, "http://", 7) != 0) return -1;
    const char *p = proxy + 7;
    char auth[512] = "";
    const char *at = strchr(p, '@');
    const char *hostport = p;
    if (at) {
        size_t n = (size_t)(at - p);
        if (n >= sizeof auth) return -1;
        memcpy(auth, p, n); auth[n] = '\0';
        hostport = at + 1;
    }
    char phost[256];
    int pport = 3128;
    const char *slash = strchr(hostport, '/');
    size_t hlen = slash ? (size_t)(slash - hostport) : strlen(hostport);
    const char *colon = memchr(hostport, ':', hlen);
    if (colon) {
        hlen = (size_t)(colon - hostport);
        pport = atoi(colon + 1);
    }
    if (hlen >= sizeof phost) return -1;
    memcpy(phost, hostport, hlen); phost[hlen] = '\0';

    int fd = connect_host(phost, pport);
    if (fd < 0) return -1;
    char req[1024];
    int n = snprintf(req, sizeof req,
        "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n", host, port, host, port);
    if (auth[0]) {
        char b64[1024];
        int bl = EVP_EncodeBlock((unsigned char *)b64,
                                 (unsigned char *)auth, (int)strlen(auth));
        b64[bl] = '\0';
        n += snprintf(req + n, sizeof req - (size_t)n,
                      "Proxy-Authorization: Basic %s\r\n", b64);
    }
    n += snprintf(req + n, sizeof req - (size_t)n, "\r\n");
    if (send(fd, req, (size_t)n, 0) < 0) { close(fd); return -1; }
    /* Read CONNECT reply headers until blank line. */
    char buf[4096];
    size_t total = 0;
    ssize_t r;
    while (total + 1 < sizeof buf &&
           (r = recv(fd, buf + total, sizeof buf - total - 1, 0)) > 0) {
        total += (size_t)r;
        buf[total] = '\0';
        if (strstr(buf, "\r\n\r\n")) break;
    }
    int status = 0;
    sscanf(buf, "HTTP/%*s %d", &status);
    if (status != 200) { close(fd); return -1; }
    return fd;
}

int feilian_https(feilian_client *c, const char *method, const char *url,
                  const char *json_body, char *body, size_t cap) {
    if (strncmp(url, "https://", 8) != 0) return -1;
    const char *host_start = url + 8;
    const char *path = strchr(host_start, '/');
    char host[256];
    int port = 443;
    if (!path) path = "/";
    size_t host_len = (size_t)(path - host_start);
    const char *colon = memchr(host_start, ':', host_len);
    if (colon) {
        host_len = (size_t)(colon - host_start);
        port = atoi(colon + 1);
    }
    if (host_len >= sizeof host) return -1;
    memcpy(host, host_start, host_len);
    host[host_len] = '\0';

    int fd = connect_via_proxy(host, port);
    if (fd < 0) fd = connect_host(host, port);
    if (fd < 0) return -1;

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host);
    SSL_set_alpn_protos(ssl, (unsigned char *)"\x08http/1.1", 9);
    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl); SSL_CTX_free(ctx); close(fd); return -1;
    }

    char req[8192];
    int n = snprintf(req, sizeof req,
        "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
        "Content-Type: application/json\r\nAccept: application/json\r\n"
        "Accept-Language: en\r\n",
        method, path, host, FEILIAN_USER_AGENT);
    if (c->cookies[0])
        n += snprintf(req + n, sizeof req - (size_t)n, "Cookie: %s\r\n", c->cookies);
    if (json_body)
        n += snprintf(req + n, sizeof req - (size_t)n,
                      "Content-Length: %zu\r\n", strlen(json_body));
    n += snprintf(req + n, sizeof req - (size_t)n, "Connection: close\r\n\r\n");
    if (json_body)
        n += snprintf(req + n, sizeof req - (size_t)n, "%s", json_body);
    SSL_write(ssl, req, n);

    /* Read everything, split headers/body on \r\n\r\n. */
    char *all = malloc(1 << 20);
    size_t total = 0, alloc = 1 << 20;
    int r;
    while ((r = SSL_read(ssl, all + total, (int)(alloc - total - 1))) > 0) {
        total += (size_t)r;
        if (total + 4096 >= alloc) break;
    }
    all[total] = '\0';
    SSL_shutdown(ssl);
    SSL_free(ssl); SSL_CTX_free(ctx); close(fd);

    int status = -1;
    sscanf(all, "HTTP/%*s %d", &status);
    char *hdr_end = strstr(all, "\r\n\r\n");
    if (hdr_end) {
        *hdr_end = '\0';
        accumulate_cookies(c, all);
        /* Server Date -> TOTP time offset (server clock minus local). */
        const char *dp = strcasestr(all, "\r\nDate:");
        if (dp) {
            struct tm tm = {0};
            if (strptime(dp + 7, "%a, %d %b %Y %H:%M:%S GMT", &tm)) {
                time_t srv = timegm(&tm);
                if (srv != (time_t)-1) c->date_offset_sec = (long)(srv - time(NULL));
            }
        }
        const char *b = hdr_end + 4;
        /* Chunked transfer: de-chunk minimally (first chunk only is
         * enough for the small JSON replies here; full de-chunking is a TODO). */
        if (strcasestr(all, "Transfer-Encoding: chunked")) {
            /* Parse hex chunk sizes and concatenate. */
            size_t out = 0;
            const char *p = b;
            while (*p && out + 1 < cap) {
                long sz = strtol(p, NULL, 16);
                if (sz <= 0) break;
                const char *data = strstr(p, "\r\n");
                if (!data) break;
                data += 2;
                size_t take = (size_t)sz;
                if (out + take >= cap) take = cap - out - 1;
                memcpy(body + out, data, take);
                out += take;
                p = data + sz + 2;
            }
            body[out] = '\0';
        } else {
            strncpy(body, b, cap - 1);
            body[cap - 1] = '\0';
        }
    } else {
        body[0] = '\0';
    }
    free(all);
    return status;
}

static int build_url(char *out, size_t cap, const char *server,
                     const char *tmpl, const char *os, const char *ver) {
    /* tmpl is like "/api/login?os=%s&os_version=%s" */
    char path[512];
    snprintf(path, sizeof path, tmpl, os, ver);
    size_t sl = strlen(server);
    while (sl > 0 && server[sl - 1] == '/') sl--;
    snprintf(out, cap, "%.*s%s", (int)sl, server, path);
    return 0;
}

int feilian_match_company(feilian_client *c, char *err, size_t err_cap) {
    char payload[256], body[8192];
    snprintf(payload, sizeof payload, "{\"code\":\"%s\"}", c->company);
    /* /api/match is a standalone POST, not via feilian_https' cookie
     * handling for the server URL — reuse it with a throwaway client. */
    feilian_client tmp = *c;
    tmp.cookies[0] = '\0';
    int st = feilian_https(&tmp, "POST", FEILIAN_MATCH_URL, payload, body, sizeof body);
    if (st != 200) { snprintf(err, err_cap, "match: HTTP %d: %.200s", st, body); return -1; }
    if (feilian_json_code(body) != 0) {
        char msg[256] = "";
        feilian_json_string(body, "message", msg, sizeof msg);
        snprintf(err, err_cap, "match: %s", msg[0] ? msg : body);
        return -1;
    }
    char url[512];
    /* The reply's server is in data.domain (RespCompany.Domain),
     * e.g. "https://test.ifeilian.cn:443" — not "url". */
    if (feilian_json_string(body, "domain", url, sizeof url) < 0 &&
        feilian_json_string(body, "url", url, sizeof url) < 0 &&
        feilian_json_string(body, "server", url, sizeof url) < 0) {
        snprintf(err, err_cap, "match: no url in reply: %.200s", body);
        return -1;
    }
    strncpy(c->server, url, sizeof c->server - 1);
    c->server[sizeof c->server - 1] = '\0';
    /* Keep any cookies the match call set. */
    strncpy(c->cookies, tmp.cookies, sizeof c->cookies - 1);
    return 0;
}

int feilian_login_setting(feilian_client *c, char *body, size_t cap) {
    char url[1024];
    build_url(url, sizeof url, c->server, "/api/login/setting?os=%s&os_version=%s",
              c->os, c->os_version);
    return feilian_https(c, "GET", url, NULL, body, cap);
}

int feilian_login_password(feilian_client *c, const char *password,
                           char *body, size_t cap) {
    char pw_hex[65];
    if (strlen(password) == 64) {
        int hex = 1;
        for (int i = 0; password[i]; i++)
            if (!((password[i] >= '0' && password[i] <= '9') ||
                  (password[i] >= 'a' && password[i] <= 'f') ||
                  (password[i] >= 'A' && password[i] <= 'F'))) hex = 0;
        if (hex) strncpy(pw_hex, password, sizeof pw_hex - 1);
        else feilian_sha256_hex(password, pw_hex);
    } else {
        feilian_sha256_hex(password, pw_hex);
    }
    pw_hex[64] = '\0';
    char payload[1024], url[1024];
    snprintf(payload, sizeof payload,
             "{\"user_name\":\"%s\",\"password\":\"%s\",\"platform\":\"feilian\"}",
             c->username, pw_hex);
    build_url(url, sizeof url, c->server, "/api/login?os=%s&os_version=%s",
              c->os, c->os_version);
    int st = feilian_https(c, "POST", url, payload, body, cap);
    if (st == 200 && feilian_json_code(body) == 0) c->logged_in = 1;
    /* The password hash is in `payload` only, on the stack. */
    memset(payload, 0, sizeof payload);
    return st;
}

int feilian_list_vpn(feilian_client *c, char *body, size_t cap) {
    char url[1024];
    build_url(url, sizeof url, c->server, "/api/vpn/list?os=%s&os_version=%s",
              c->os, c->os_version);
    return feilian_https(c, "GET", url, NULL, body, cap);
}

int feilian_fetch_peer(feilian_client *c, const char *vpn_base_url,
                       const char *public_key, char *body, size_t cap) {
    return feilian_fetch_peer_otp(c, vpn_base_url, public_key, NULL, body, cap);
}

int feilian_fetch_peer_otp(feilian_client *c, const char *vpn_base_url,
                           const char *public_key, const char *otp,
                           char *body, size_t cap) {
    char payload[512], url[1024];
    if (otp && otp[0])
        snprintf(payload, sizeof payload,
                 "{\"public_key\":\"%s\",\"otp\":\"%s\"}", public_key, otp);
    else
        snprintf(payload, sizeof payload, "{\"public_key\":\"%s\"}", public_key);
    const char *base = vpn_base_url && vpn_base_url[0] ? vpn_base_url : c->server;
    build_url(url, sizeof url, base, "/vpn/conn?os=%s&os_version=%s",
              c->os, c->os_version);
    return feilian_https(c, "POST", url, payload, body, cap);
}

int feilian_get_otp_uri(feilian_client *c, char *body, size_t cap) {
    char url[1024];
    build_url(url, sizeof url, c->server, "/api/v2/p/otp?os=%s&os_version=%s",
              c->os, c->os_version);
    return feilian_https(c, "GET", url, NULL, body, cap);
}

int feilian_mfa_type(feilian_client *c, char *body, size_t cap) {
    char url[1024];
    build_url(url, sizeof url, c->server, "/api/mfa/type?os=%s&os_version=%s",
              c->os, c->os_version);
    return feilian_https(c, "GET", url, NULL, body, cap);
}

int feilian_mfa_send(feilian_client *c, const char *mfa_type,
                     char *body, size_t cap) {
    char payload[512], url[1024];
    snprintf(payload, sizeof payload,
             "{\"mfa_type\":\"%s\",\"login_scene\":\"login\",\"account\":\"%s\"}",
             mfa_type, c->username);
    build_url(url, sizeof url, c->server, "/api/v1/login/mfa/send?os=%s&os_version=%s",
              c->os, c->os_version);
    return feilian_https(c, "POST", url, payload, body, cap);
}

int feilian_mfa_verify(feilian_client *c, const char *mfa_type,
                       const char *code, char *body, size_t cap) {
    char payload[1024], url[1024];
    if (strcmp(mfa_type, "password") == 0) {
        char pw_hex[65];
        feilian_sha256_hex(code, pw_hex);
        snprintf(payload, sizeof payload,
                 "{\"mfa_type\":\"password\",\"login_scene\":\"login\",\"account\":\"%s\",\"password\":\"%s\",\"code\":\"\"}",
                 c->username, pw_hex);
    } else {
        snprintf(payload, sizeof payload,
                 "{\"mfa_type\":\"%s\",\"login_scene\":\"login\",\"account\":\"%s\",\"code\":\"%s\"}",
                 mfa_type, c->username, code);
    }
    build_url(url, sizeof url, c->server, "/api/v1/login/mfa/verify?os=%s&os_version=%s",
              c->os, c->os_version);
    return feilian_https(c, "POST", url, payload, body, cap);
}

/* Base32 decode (RFC 4648, uppercase, padding optional). */
static int b32_decode(const char *in, unsigned char *out, size_t cap) {
    size_t n = 0;
    int bits = 0, val = 0;
    for (const char *p = in; *p; p++) {
        int v;
        if (*p >= 'A' && *p <= 'Z') v = *p - 'A';
        else if (*p >= 'a' && *p <= 'z') v = *p - 'a';
        else if (*p >= '2' && *p <= '7') v = *p - '2' + 26;
        else if (*p == '=') break;
        else continue;
        val = (val << 5) | v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (n >= cap) return -1;
            out[n++] = (unsigned char)((val >> bits) & 0xff);
        }
    }
    return (int)n;
}

int feilian_totp(feilian_client *c, const char *secret, char *out6) {
    unsigned char key[128];
    int klen = b32_decode(secret, key, sizeof key);
    if (klen <= 0) return -1;
    long long counter = (long long)(time(NULL) + c->date_offset_sec) / 30;
    unsigned char msg[8];
    for (int i = 7; i >= 0; i--) { msg[i] = (unsigned char)(counter & 0xff); counter >>= 8; }
    unsigned char hmac[20];
    unsigned int hlen = 0;
    if (!HMAC(EVP_sha1(), key, klen, msg, 8, hmac, &hlen)) return -1;
    int off = hmac[19] & 0x0f;
    int code = ((hmac[off] & 0x7f) << 24) | (hmac[off + 1] << 16) |
               (hmac[off + 2] << 8) | hmac[off + 3];
    snprintf(out6, 7, "%06d", code % 1000000);
    return 0;
}

int feilian_gen_wg_keypair(char *private_b64, size_t priv_cap,
                           char *public_b64, size_t pub_cap) {
    unsigned char priv[32];
    if (RAND_bytes(priv, 32) != 1) return -1;
    /* WireGuard Curve25519 clamping. */
    priv[0] &= 248;
    priv[31] &= 127;
    priv[31] |= 64;

    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
    if (!pkey) return -1;
    unsigned char pub[32];
    size_t pub_len = 32;
    if (EVP_PKEY_get_raw_public_key(pkey, pub, &pub_len) != 1) {
        EVP_PKEY_free(pkey); return -1;
    }
    EVP_PKEY_free(pkey);

    /* Base64 via EVP_EncodeBlock. */
    char tmp[64];
    int n = EVP_EncodeBlock((unsigned char *)tmp, priv, 32);
    tmp[n] = '\0';
    strncpy(private_b64, tmp, priv_cap - 1); private_b64[priv_cap - 1] = '\0';
    n = EVP_EncodeBlock((unsigned char *)tmp, pub, 32);
    tmp[n] = '\0';
    strncpy(public_b64, tmp, pub_cap - 1); public_b64[pub_cap - 1] = '\0';
    return 0;
}

int feilian_write_wg_conf(const char *path, const char *address,
                          const char *private_key, const char *peer_key,
                          const char *endpoint, const char *dns, int mtu) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fprintf(f, "[Interface]\nPrivateKey = %s\nAddress = %s\n",
            private_key, address);
    if (dns && dns[0]) fprintf(f, "DNS = %s\n", dns);
    if (mtu > 0) fprintf(f, "MTU = %d\n", mtu);
    fprintf(f, "\n[Peer]\nPublicKey = %s\nEndpoint = %s\n"
               "AllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n",
            peer_key, endpoint);
    fclose(f);
    return 0;
}
