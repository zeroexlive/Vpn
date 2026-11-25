#define _GNU_SOURCE 1
#define _DEFAULT_SOURCE 1
#include "feilian.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
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

/* AES password encryption, as used by the SealSuite web portal
 * (portal 3.3.14, module 90949) and the official client's
 * aesEncryptIv — verified against the user's server:
 * plain password -> 40000 "Parameter is invalid",
 * this encryption -> 10110001 "user name or password is incorrect"
 * for a dummy account, i.e. a valid parameter.
 *
 *   key_str = MD5("9007199254740991") as lowercase hex (32 chars)
 *   key     = UTF-8 bytes of key_str (32 bytes -> AES-256)
 *   iv      = first 16 chars of SHA1(key_str) hex, as ASCII
 *   cipher  = AES-256-CBC, PKCS#7, output lowercase hex
 * No IV is prepended; the output is deterministic. */
int feilian_aes_encrypt_password(const char *password, char *out_hex, size_t cap) {
    unsigned char md5d[MD5_DIGEST_LENGTH];
    MD5((const unsigned char *)"9007199254740991", 16, md5d);
    char key_str[33];
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
        snprintf(key_str + i * 2, 3, "%02x", md5d[i]);
    key_str[32] = '\0';
    unsigned char sha1d[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char *)key_str, 32, sha1d);
    char sha1_hex[41];
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
        snprintf(sha1_hex + i * 2, 3, "%02x", sha1d[i]);
    sha1_hex[40] = '\0';
    unsigned char iv[16];
    memcpy(iv, sha1_hex, 16); /* first 16 ASCII chars of SHA1 hex */
    size_t plen = strlen(password);
    size_t need = (plen / 16 + 1) * 32 + 1; /* hex of padded blocks */
    if (cap < need) return -1;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int outlen = 0, tmplen = 0;
    unsigned char *ct = malloc((plen / 16 + 1) * 16);
    if (!ct) { EVP_CIPHER_CTX_free(ctx); return -1; }
    int ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                                (const unsigned char *)key_str, iv) == 1 &&
             EVP_EncryptUpdate(ctx, ct, &outlen,
                               (const unsigned char *)password, (int)plen) == 1 &&
             EVP_EncryptFinal_ex(ctx, ct + outlen, &tmplen) == 1;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) { free(ct); return -1; }
    outlen += tmplen;
    for (int i = 0; i < outlen; i++)
        snprintf(out_hex + i * 2, 3, "%02x", ct[i]);
    out_hex[outlen * 2] = '\0';
    free(ct);
    return 0;
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
        if (*p == '\\' && p[1]) {
            p++;
            switch (*p) {
                case 'n': out[i++] = '\n'; p++; continue;
                case 'r': out[i++] = '\r'; p++; continue;
                case 't': out[i++] = '\t'; p++; continue;
                case 'b': out[i++] = '\b'; p++; continue;
                case 'f': out[i++] = '\f'; p++; continue;
                default: break;
            }
        }
        out[i++] = *p++;
    }
    out[i] = '\0';
    return (int)i;
}

/* Find "key":true/false. Returns 1/0, or -1 if absent. */
static int feilian_json_bool(const char *body, const char *key) {
    char pat[128];
    snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *p = strstr(body, pat);
    if (!p) return -1;
    p = strchr(p + strlen(pat), ':');
    if (!p) return -1;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (strncmp(p, "true", 4) == 0) return 1;
    if (strncmp(p, "false", 5) == 0) return 0;
    return -1;
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

/* Plain TCP connect, no TLS. 10 s timeout, tries every resolved
 * address. Returns fd or -1, with *err set to a plain-English reason. */
static int connect_host(const char *host, int port, char *err, size_t err_cap) {
    struct addrinfo hints = {0}, *res = NULL, *ai;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char port_s[16];
    snprintf(port_s, sizeof port_s, "%d", port);
    if (getaddrinfo(host, port_s, &hints, &res) != 0) {
        snprintf(err, err_cap, "DNS lookup failed for %s — check internet / DNS", host);
        return -1;
    }
    int last_errno = 0;
    for (ai = res; ai; ai = ai->ai_next) {
        int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) { last_errno = errno; continue; }
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        int rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (rc != 0 && errno == EINPROGRESS) {
            fd_set wf; FD_ZERO(&wf); FD_SET(fd, &wf);
            struct timeval tv = {10, 0};
            rc = select(fd + 1, NULL, &wf, NULL, &tv);
            if (rc > 0) {
                int so_err = 0; socklen_t sl = sizeof so_err;
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &sl);
                if (so_err == 0) rc = 0; else { errno = so_err; rc = -1; }
            } else if (rc == 0) { errno = ETIMEDOUT; rc = -1; }
        }
        if (rc == 0) {
            fcntl(fd, F_SETFL, flags);
            struct timeval tv = {15, 0};
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
            freeaddrinfo(res);
            return fd;
        }
        last_errno = errno;
        close(fd);
    }
    freeaddrinfo(res);
    if (last_errno == ETIMEDOUT)
        snprintf(err, err_cap, "TCP connect to %s:%d timed out after 10 s — server/proxy unreachable or blocked", host, port);
    else
        snprintf(err, err_cap, "TCP connect to %s:%d failed: %s — check internet, firewall, or proxy", host, port, strerror(last_errno));
    return -1;
}

/* If https_proxy/HTTPS_PROXY is set, tunnel through it with CONNECT.
 * Returns a connected fd (to the target, via proxy) or -1. */
static int connect_via_proxy(const char *host, int port, char *err, size_t err_cap) {
    const char *proxy = getenv("https_proxy");
    if (!proxy || !proxy[0]) proxy = getenv("HTTPS_PROXY");
    if (!proxy || !proxy[0]) proxy = getenv("http_proxy");
    if (!proxy || !proxy[0]) proxy = getenv("HTTP_PROXY");
    if (!proxy || !proxy[0]) return -1;
    if (strncmp(proxy, "http://", 7) != 0 && strncmp(proxy, "https://", 8) != 0) return -1;
    const char *p = strstr(proxy, "://") + 3;
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

    char perr[512] = "";
    int fd = connect_host(phost, pport, perr, sizeof perr);
    if (fd < 0) { snprintf(err, err_cap, "proxy %s:%d unreachable: %s", phost, pport, perr); return -1; }
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
    if (status != 200) {
        snprintf(err, err_cap, "proxy refused CONNECT to %s:%d, proxy replied HTTP %d — check proxy / credentials", host, port, status);
        close(fd); return -1;
    }
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

    c->last_error[0] = '\0';
    char conn_err[512] = "";
    int fd = connect_via_proxy(host, port, conn_err, sizeof conn_err);
    if (fd < 0) {
        if (conn_err[0]) {
            strncpy(c->last_error, conn_err, sizeof c->last_error - 1);
            return -1;
        }
        fd = connect_host(host, port, c->last_error, sizeof c->last_error);
    }
    if (fd < 0) return -1;

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (c->self_signed_cert[0]) {
        /* Trust the corp cert the match reply gave us (official client
         * does the same — the bridge trusts enable_self_signed /
         * self_signed_cert). This is what makes login/setting work
         * against self-signed deployments instead of failing TLS. */
        BIO *bio = BIO_new_mem_buf(c->self_signed_cert, -1);
        X509 *cert = bio ? PEM_read_bio_X509(bio, NULL, NULL, NULL) : NULL;
        if (cert) {
            X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), cert);
            X509_free(cert);
        }
        if (bio) BIO_free(bio);
    } else if (c->enable_self_signed) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host);
    SSL_set_alpn_protos(ssl, (unsigned char *)"\x08http/1.1", 9);
    if (SSL_connect(ssl) != 1) {
        unsigned long e = ERR_get_error();
        char errbuf[256] = "";
        if (e) ERR_error_string_n(e, errbuf, sizeof errbuf);
        long verify = SSL_get_verify_result(ssl);
        snprintf(c->last_error, sizeof c->last_error,
                 "TLS handshake failed to %s (%s, verify=%ld) — server may use a self-signed cert, or TLS is blocked",
                 host, errbuf[0] ? errbuf : "no OpenSSL detail", verify);
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
    feilian_client tmp = *c;
    tmp.cookies[0] = '\0';
    /* Official 3.2.16 base first, legacy volcengine base as fallback. */
    int st = feilian_https(&tmp, "POST", FEILIAN_MATCH_URL, payload, body, sizeof body);
    if (st != 200 || feilian_json_code(body) != 0) {
        feilian_client tmp2 = *c;
        tmp2.cookies[0] = '\0';
        char body2[8192];
        int st2 = feilian_https(&tmp2, "POST", FEILIAN_MATCH_URL_LEGACY, payload, body2, sizeof body2);
        if (st2 == 200 && feilian_json_code(body2) == 0) {
            tmp = tmp2;
            strncpy(body, body2, sizeof body - 1);
            st = st2;
        }
    }
    if (st != 200) {
        if (st == -1)
            snprintf(err, err_cap, "match: %s", tmp.last_error[0] ? tmp.last_error : "no response from server");
        else
            snprintf(err, err_cap, "match: HTTP %d: %.200s", st, body);
        strncpy(c->last_error, tmp.last_error, sizeof c->last_error - 1);
        return -1;
    }
    if (feilian_json_code(body) != 0) {
        char msg[256] = "";
        feilian_json_string(body, "message", msg, sizeof msg);
        snprintf(err, err_cap, "match: %s", msg[0] ? msg : body);
        return -1;
    }
    /* Self-signed cert the server gave us — needed for TLS to it. */
    int ss = feilian_json_bool(body, "enable_self_signed");
    if (ss >= 0) c->enable_self_signed = ss;
    feilian_json_string(body, "self_signed_cert", c->self_signed_cert, sizeof c->self_signed_cert);
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
    /* 3.2.16: GET /api/login/setting, no query params, no os. */
    char url[1024];
    size_t sl = strlen(c->server);
    while (sl > 0 && c->server[sl - 1] == '/') sl--;
    snprintf(url, sizeof url, "%.*s/api/login/setting", (int)sl, c->server);
    return feilian_https(c, "GET", url, NULL, body, cap);
}

/* Extract data.next.action from the double envelope:
 * outer {"code":0,"data":"{\"next\":{\"action\":\"main\",...}}"}
 * data is a JSON string, so "action" is escaped inside it. */
int feilian_next_action(const char *body, char *out, size_t cap) {
    const char *d = strstr(body, "\"data\"");
    if (!d) return -1;
    const char *a = strstr(d, "action");
    if (!a) return -1;
    /* a points at action (possibly \"action\" in the escaped string);
     * find the value after the next ':' and '"' */
    const char *p = strchr(a, ':');
    if (!p) return -1;
    p++;
    while (*p && (*p == ' ' || *p == '"' || *p == '\\')) p++;
    size_t i = 0;
    while (*p && *p != '"' && *p != '\\' && i + 1 < cap) out[i++] = *p++;
    out[i] = '\0';
    return i > 0 ? 0 : -1;
}

int feilian_login_password(feilian_client *c, const char *password,
                           char *body, size_t cap) {
    /* 3.2.16: POST /api/v1/login, no query params.
     * {"login_scene":"feilian","account_type":"email",
     *  "account":"<email>","password":"<aesEncryptIv(password)>"}
     * The encryption is the portal's aesEncrypt (see
     * feilian_aes_encrypt_password): MD5/SHA1-derived fixed
     * key/IV, AES-256-CBC, hex output. Verified against the
     * user's server — plain is rejected with 40000, this is
     * accepted as a parameter (10110001 for a dummy account). */
    char pw[256];
    /* Trim leading/trailing whitespace only — keep inner spaces. */
    strncpy(pw, password, sizeof pw - 1); pw[sizeof pw - 1] = '\0';
    size_t n = strlen(pw);
    while (n > 0 && (pw[n - 1] == ' ' || pw[n - 1] == '\t' || pw[n - 1] == '\n' || pw[n - 1] == '\r')) pw[--n] = '\0';
    char *s = pw;
    while (*s == ' ' || *s == '\t') s++;
    char pw_hex[1024];
    if (feilian_aes_encrypt_password(s, pw_hex, sizeof pw_hex) != 0) {
        snprintf(body, cap, "{\"code\":-1,\"message\":\"AES encryption failed\"}");
        return -1;
    }
    char payload[2048], url[1024];
    const char *atype = strchr(c->username, '@') ? "email" : "email";
    snprintf(payload, sizeof payload,
             "{\"login_scene\":\"feilian\",\"account_type\":\"%s\",\"account\":\"%s\",\"password\":\"%s\"}",
             atype, c->username, pw_hex);
    size_t sl = strlen(c->server);
    while (sl > 0 && c->server[sl - 1] == '/') sl--;
    snprintf(url, sizeof url, "%.*s/api/v1/login", (int)sl, c->server);
    int st = feilian_https(c, "POST", url, payload, body, cap);
    if (st == 200 && feilian_json_code(body) == 0) {
        char action[64] = "";
        if (feilian_next_action(body, action, sizeof action) == 0 &&
            strcmp(action, "main") == 0)
            c->logged_in = 1;
        /* next.action == "2FA" / "ChangeInitPassword" / etc. is NOT
         * a plain success — the caller must route on it. */
    }
    memset(payload, 0, sizeof payload);
    memset(pw, 0, sizeof pw);
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
             "{\"mfa_type\":\"%s\",\"login_scene\":\"feilian\",\"account\":\"%s\"}",
             mfa_type, c->username);
    build_url(url, sizeof url, c->server, "/api/v1/login/mfa/send?os=%s&os_version=%s",
              c->os, c->os_version);
    return feilian_https(c, "POST", url, payload, body, cap);
}

int feilian_mfa_verify(feilian_client *c, const char *mfa_type,
                       const char *code, char *body, size_t cap) {
    char payload[2048], url[1024];
    if (strcmp(mfa_type, "password") == 0) {
        char pw_hex[1024];
        feilian_aes_encrypt_password(code, pw_hex, sizeof pw_hex);
        snprintf(payload, sizeof payload,
                 "{\"mfa_type\":\"password\",\"login_scene\":\"feilian\",\"account\":\"%s\",\"password\":\"%s\",\"code\":\"\"}",
                 c->username, pw_hex);
    } else {
        snprintf(payload, sizeof payload,
                 "{\"mfa_type\":\"%s\",\"login_scene\":\"feilian\",\"account\":\"%s\",\"code\":\"%s\"}",
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
