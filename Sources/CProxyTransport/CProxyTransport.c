#include "CProxyTransport.h"
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <time.h>
struct vpg_channel { CURL *curl; curl_socket_t fd; };
static pthread_once_t once = PTHREAD_ONCE_INIT;
static CURLcode global_result;
static void initialize(void) { global_result = curl_global_init(CURL_GLOBAL_DEFAULT); }
static curl_socket_t open_socket(void *unused, curlsocktype purpose, struct curl_sockaddr *address) {
    (void)unused; (void)purpose;
    int fd = socket(address->family, address->socktype, address->protocol);
    if(fd < 0) return CURL_SOCKET_BAD;
    if(fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) { close(fd); return CURL_SOCKET_BAD; }
    int yes = 1;
    if(setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes)) < 0) { close(fd); return CURL_SOCKET_BAD; }
    return fd;
}
static CURL *configured(const char *proxy, const char *target, const char *user, const char *password, int *error) {
    pthread_once(&once, initialize);
    if(global_result != CURLE_OK) { *error = global_result; return NULL; }
    CURL *curl = curl_easy_init();
    if(!curl) { *error = CURLE_OUT_OF_MEMORY; return NULL; }
    CURLcode result;
#define SET(option, value) do { result = curl_easy_setopt(curl, option, value); if(result != CURLE_OK) goto fail; } while(0)
    /* Explicit proxy and empty bypass list override all environment proxy settings. */
    SET(CURLOPT_PROXY, proxy);
    SET(CURLOPT_NOPROXY, "");
    SET(CURLOPT_URL, target);
    SET(CURLOPT_HTTPPROXYTUNNEL, 1L);
    SET(CURLOPT_NOSIGNAL, 1L);
    SET(CURLOPT_CONNECTTIMEOUT_MS, 8000L);
    SET(CURLOPT_TIMEOUT_MS, 12000L);
    SET(CURLOPT_FOLLOWLOCATION, 0L);
    SET(CURLOPT_MAXREDIRS, 0L);
    SET(CURLOPT_PROTOCOLS, (long)(CURLPROTO_HTTP | CURLPROTO_HTTPS));
    SET(CURLOPT_REDIR_PROTOCOLS, (long)CURLPROTO_HTTPS);
    SET(CURLOPT_SSL_VERIFYPEER, 1L);
    SET(CURLOPT_SSL_VERIFYHOST, 2L);
    SET(CURLOPT_PROXY_SSL_VERIFYPEER, 1L);
    SET(CURLOPT_PROXY_SSL_VERIFYHOST, 2L);
    SET(CURLOPT_OPENSOCKETFUNCTION, open_socket);
    SET(CURLOPT_NETRC, (long)CURL_NETRC_IGNORED);
    SET(CURLOPT_SUPPRESS_CONNECT_HEADERS, 1L);
    if(user) {
        SET(CURLOPT_PROXYUSERNAME, user);
        SET(CURLOPT_PROXYPASSWORD, password ? password : "");
        SET(CURLOPT_PROXYAUTH, (long)CURLAUTH_BASIC);
    }
#undef SET
    return curl;
fail:
    *error = result; curl_easy_cleanup(curl); return NULL;
}
vpg_channel *vpg_connect(const char *proxy, const char *target, const char *user, const char *password, int *error) {
    *error = 0;
    CURL *curl = configured(proxy, target, user, password, error);
    if(!curl) return NULL;
    CURLcode result = curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);
    if(result == CURLE_OK) result = curl_easy_perform(curl);
    curl_socket_t fd = CURL_SOCKET_BAD;
    if(result == CURLE_OK) result = curl_easy_getinfo(curl, CURLINFO_ACTIVESOCKET, &fd);
    if(result != CURLE_OK || fd == CURL_SOCKET_BAD) { *error = result ? result : CURLE_COULDNT_CONNECT; curl_easy_cleanup(curl); return NULL; }
    vpg_channel *channel = calloc(1, sizeof(*channel));
    if(!channel) { *error = CURLE_OUT_OF_MEMORY; curl_easy_cleanup(curl); return NULL; }
    channel->curl = curl; channel->fd = fd; return channel;
}
int vpg_descriptor(vpg_channel *channel) { return channel->fd; }
int vpg_send(vpg_channel *channel, const void *bytes, size_t count) {
    size_t offset = 0;
    struct timespec start, now; clock_gettime(CLOCK_MONOTONIC, &start);
    while(offset < count) {
        size_t sent = 0;
        CURLcode result = curl_easy_send(channel->curl, (const char *)bytes + offset, count - offset, &sent);
        if(result == CURLE_OK && sent > 0) { offset += sent; }
        else if(result == CURLE_AGAIN) {
            struct pollfd p = { channel->fd, POLLOUT, 0 };
            int ready = poll(&p, 1, 100);
            if(ready < 0 || (ready > 0 && (p.revents & (POLLERR | POLLHUP | POLLNVAL)))) return 0;
        } else return 0;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if(now.tv_sec - start.tv_sec >= 10) return 0;
    }
    return 1;
}
int vpg_receive(vpg_channel *channel, void *bytes, size_t count) {
    size_t received = 0;
    CURLcode result = curl_easy_recv(channel->curl, bytes, count, &received);
    if(result == CURLE_AGAIN) return -2;
    if(result != CURLE_OK) return -1;
    return (int)received;
}
void vpg_close(vpg_channel *channel) { if(channel) { curl_easy_cleanup(channel->curl); free(channel); } }
struct response { char *bytes; size_t size; };
static size_t append_response(char *bytes, size_t size, size_t count, void *context) {
    struct response *response = context;
    if(size != 0 && count > 65536 / size) return 0;
    size_t length = size * count;
    if(length > 65536 - response->size) return 0;
    char *new_bytes = realloc(response->bytes, response->size + length + 1);
    if(!new_bytes) return 0;
    response->bytes = new_bytes;
    memcpy(response->bytes + response->size, bytes, length);
    response->size += length; response->bytes[response->size] = 0; return length;
}
int vpg_trace(const char *proxy, const char *user, const char *password, char **output) {
    int error = 0; *output = NULL;
    CURL *curl = configured(proxy, "https://www.cloudflare.com/cdn-cgi/trace", user, password, &error);
    if(!curl) return error;
    struct response response = {NULL, 0};
    CURLcode result = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, append_response);
    if(result == CURLE_OK) result = curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    if(result == CURLE_OK) result = curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
    if(result == CURLE_OK) result = curl_easy_perform(curl);
    long code = 0;
    if(result == CURLE_OK) result = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    if(result == CURLE_OK && code != 200) result = CURLE_HTTP_RETURNED_ERROR;
    curl_easy_cleanup(curl);
    if(result != CURLE_OK || !response.bytes) { free(response.bytes); return result ? result : CURLE_GOT_NOTHING; }
    *output = response.bytes; return 0;
}
void vpg_free(void *pointer) { free(pointer); }
