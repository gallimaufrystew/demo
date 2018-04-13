///
/// help.h
///

#ifndef TUNS_CORE_INCLUDED_H_
#define TUNS_CORE_INCLUDED_H_

#ifdef __linux__
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdbool.h>
#elif _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <process.h>
#endif

#ifdef _WIN32
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"libcrypto.lib")
#pragma comment(lib,"libssl.lib")
#endif

#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <map>
#include <unordered_map>

#define CUSTOM_EXT_TYPE_1000 10000

#define PROTO_HEAD_SIZE   12
#define USER_MSG_SIZE     80 * 1024

typedef struct {
    bool verify_peer;
    /* bool connected; */
    int fd;
    SSL *ssl;
    int client;
    SSL_CTX *ssl_old_ctx;
    SSL_CTX *ssl_new_ctx;
} ssl_session_t;

int open_socket(int port);
void close_sock(int fd);
void waste_time(uint32_t seconds);
int open_upstream(int port);
int init_libssl();
void clean_up(ssl_session_t *session);
void clean_up_ssl(ssl_session_t *session);
int init_ssl_service(ssl_session_t *session);
SSL_CTX *create_ssl_ctx(const char *sign_algo);
int create_ssl_context(ssl_session_t *session);
int handle_ssl_accept_client(ssl_session_t *session);
int handle_ssl_read(ssl_session_t *session);
int handle_upstream_read(int fd, ssl_session_t *session);

#endif /* HELP_H_ */
