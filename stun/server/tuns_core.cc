///
/// help function
///

#ifndef HELP_INCLUDED_CC_
#define HELP_INCLUDED_CC_

#include "tuns_core.h"
#include "config.h"
#include "tun_socket.h"

const char *passwd = "123456", *rfb_command = "RFB_OPEN";

const int rfb_listen_port = 5900;

std::unordered_map<int, int> up_connections, down_connections;
std::unordered_map<int, std::pair<std::string, int>> port_map;

std::unordered_map<int, int> fd_type;

std::unordered_map<int, bool> connections;

static int ana_ext_callback(SSL *ssl, unsigned int ext_type,
                            const unsigned char *in, size_t inlen, int *al, void *arg);

int exact_write(int fd, void *buf, int len);
int ssl_exact_write(SSL *ssl, void *buf, int len);
int ssl_exact_read(SSL *ssl, void *buf, int len);

int handle_rfb_channel_message(int vnc_client, int port, char client_data[], int len);
int handle_other_channel_message(int fd, int port, char client_data[], int len);

int exact_write(int fd, void *buf, int len)
{
    int    bytes_left, written_bytes;
    char  *ptr = static_cast<char *>(buf);

    bytes_left = len;

    while (bytes_left > 0) {
        written_bytes = send(fd, ptr, bytes_left, 0);
        if (written_bytes <= 0) {

#if (0)
            return -1;

#elif (1)
            if (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN) {
                written_bytes = 0;
            } else {
                // todo fatal error
                std::cout << "send:" << strerror(errno) << "\n";
                return -1;
            }
#endif
        }
        bytes_left -= written_bytes;
        ptr += written_bytes;
    }
    return 0;
}

int ssl_exact_read(SSL *ssl, void *buf, int len)
{
    int    bytes_left, bytes_read;
    char  *ptr = static_cast<char *>(buf);

    if (ssl == nullptr) {
        return -1;
    }

    bytes_left = len;

    while (bytes_left > 0) {
        bytes_read = SSL_read(ssl, ptr, bytes_left);
        if (bytes_read <= 0) {
            int err = SSL_get_error(ssl, bytes_read);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                bytes_read = 0;
            } else {
                // todo fatal error
                std::cout << "SSL_read: " << err << "\n";
                return -1;
            }
        }
        bytes_left -= bytes_read;
        ptr += bytes_read;
    }
    return 0;
}

int ssl_exact_write(SSL *ssl, void *buf, int len)
{
    int    bytes_left, written_bytes;
    char  *ptr = static_cast<char *>(buf);

    bytes_left = len;

    if (ssl == nullptr) {
        return -1;
    }

    while (bytes_left > 0) {
        written_bytes = SSL_write(ssl, ptr, bytes_left);
        if (written_bytes <= 0) {
            int err = SSL_get_error(ssl, written_bytes);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                written_bytes = 0;
            } else {
                // todo fatal error
                std::cout << "SSL_write: " << err << "\n";
                return -1;
            }
        }
        bytes_left -= written_bytes;
        ptr += written_bytes;
    }
    return 0;
}

void close_sock(int fd)
{
#if __linux__
    close(fd);
#elif _WIN32
    closesocket(fd);
#endif
}

void waste_time(uint32_t seconds)
{
#if __linux__
    sleep(1000);
#elif _WIN32
    Sleep(1000);
#endif
}

int handle_ssl_read(ssl_session_t *session)
{
    char buf[PROTO_HEAD_SIZE + USER_MSG_SIZE] = { 0 };

    int n = ssl_exact_read(session->ssl, buf, PROTO_HEAD_SIZE);
    if (n != 0) {
        //session->connected = false;
        return -1;
    }

    uint32_t  len, nlen;
    memcpy(&nlen, buf, 4);
    len = ntohl(nlen);

    uint32_t  port, nport;
    memcpy(&nport, buf + 4, 4);
    port = ntohl(nport);

    uint32_t  fd, nfd;
    memcpy(&nfd, buf + 8, 4);
    fd = ntohl(nfd);

    n = ssl_exact_read(session->ssl, buf + PROTO_HEAD_SIZE, len);
    if (n != 0) {
        //session->connected = false;
        return -1;
    }

    if (port_map[port].second == rfb_listen_port) {
        return handle_rfb_channel_message(fd, port, buf + PROTO_HEAD_SIZE, len);
    } else {
        return handle_other_channel_message(fd, port, buf + PROTO_HEAD_SIZE, len);
    }
}

static int check_connection_map(int fd, int up_fd, int port)
{
    auto res = up_connections.insert(std::make_pair(fd, up_fd));
    // connection map alread exists
    if (res.second == false) {
        int old_up_fd = up_connections[fd];
        connections[old_up_fd] = false;
        close_sock(old_up_fd);
        up_connections[fd] = up_fd;
    }
    // now just replace it
    down_connections[up_fd] = fd;
    connections[up_fd] = true;
    fd_type[up_fd] = port_map[port].second;
}

int handle_rfb_channel_message(int fd, int port, char rfb_data[], int len)
{
    int cmd_len = strlen(rfb_command);
    if (memcmp(rfb_data, rfb_command, cmd_len) == 0) {
        int up_fd = open_upstream(port);
        if (up_fd > 0) {
            std::cout << "rfb command open socket " << up_fd << "\n";
            check_connection_map(fd, up_fd, port);
        }
        return up_fd;
    } else {
        int up_fd = up_connections[fd];
        int ret = exact_write(up_fd, rfb_data, len);
        if (ret != 0) {
            connections[up_fd] = false;
        }
        return 0;
    }
}

static int is_new_connection(int fd, int port)
{
    auto it = up_connections.find(fd);
    if (it == up_connections.end()) {
        return -1;
    }
    if (!connections[it->second]) {
        return -1;
    }
    if (fd_type[up_connections[fd]] != port_map[port].second) {
        return -1;
    }
    return it->second;
}

int handle_other_channel_message(int fd, int port, char other_data[], int len)
{
    int res = is_new_connection(fd, port);
    if (res < 0) {

        //connections[up_connections[fd]] = false;

        std::cout << "other client " << "fd = " << fd << " port " << port << "\n";

        int up_fd = open_upstream(port);
        if (up_fd > 0) {
            up_connections[fd] = up_fd;
            down_connections[up_fd] = fd;
            connections[up_fd] = true;

            fd_type[up_fd] = port_map[port].second;

            int ret = exact_write(up_fd, other_data, len);
            if (ret != 0) {
                connections[up_fd] = false;
                return ret;
            }
        }
        return up_fd;
    } else {
        int ret = exact_write(res, other_data, len);
        if (ret != 0) {
            connections[res] = false;
        }
        return ret;
    }
}

int handle_upstream_read(int fd, ssl_session_t *session)
{
    char buf[PROTO_HEAD_SIZE + USER_MSG_SIZE] = { 0 };

    int len = recv(fd, buf + PROTO_HEAD_SIZE, USER_MSG_SIZE, 0);
    if (len <= 0) {
        if (errno != EINTR && errno != EWOULDBLOCK && errno != EAGAIN) {
            connections[fd] = false;
        }
        return -1;
    }

    //std::cout << "upstream data size <--- " << len << '\n';

    uint32_t  nlen;
    nlen = htonl(len);
    std::memcpy(buf, &nlen, 4);

    // now port is of no importance
    // for simplicity we omit it

    uint32_t  nfd;
    nfd = htonl(down_connections[fd]);
    std::memcpy(buf + 8, &nfd, 4);

    int n = ssl_exact_write(session->ssl, buf, len + PROTO_HEAD_SIZE);
    if (n != 0) {
        //session->connected = false;
        return -1;
    }

    return 0;
}

int handle_ssl_accept_client(ssl_session_t *session)
{
    create_ssl_context(session);

    session->client = accept(session->fd, nullptr, 0);
    if (session->client <= 0) {
        return -1;
    }

    session->ssl = SSL_new(session->ssl_old_ctx);
    if (!session->ssl) {
        std::printf("SSL_new() ERR\n");
        return -1;
    }
    SSL_set_fd(session->ssl, session->client);

    if (SSL_accept(session->ssl) != 1) {
        ERR_print_errors_fp(stderr);
        close_sock(session->client);
        SSL_free(session->ssl);
        return -1;
    }

    if (session->verify_peer) {
        X509 *cert = SSL_get_peer_certificate(session->ssl);
        if (cert) {
            long ret = SSL_get_verify_result(session->ssl);
            if (ret != X509_V_OK) {
                ERR_print_errors_fp(stderr);
                std::printf("verify client failed\n");
            } else {
                std::printf("verify client ok\n");
            }
            X509_free(cert);
        } else {
            std::printf("no peer certificate\n");
        }
    }

    //session->connected = true;

    return 0;
}

int open_socket(int port)
{
    struct sockaddr_in addr = {};

    //memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);/* inet_addr("127.0.0.1") */

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket() ERR");
        exit(EXIT_FAILURE);
    }

    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(int));

    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("bind() ERR");
        exit(EXIT_FAILURE);
    }

    if (listen(fd, 5) < 0) {
        perror("listen() ERR");
        exit(EXIT_FAILURE);
    }

    return fd;
}

static void *fill_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

static int connect_by_hostname(std::string &host, int port)
{
    int   fd, rv;
    struct addrinfo hints, *servinfo, *p;
    char  s[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;// AF_UNSPEC AF_INET6
    hints.ai_socktype = SOCK_STREAM;

    char service[128] = {0};
    sprintf(service, "%d", port);

    if ((rv = getaddrinfo(host.c_str(), service, &hints, &servinfo)) != 0) {
        fprintf(stderr, "server getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    for (p = servinfo; p != nullptr; p = p->ai_next) {
        if ((fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("server socket");
            continue;
        }

        if (timeout_connect(fd, p->ai_addr, p->ai_addrlen) != 0) {
            close_sock(fd);
            continue;
        }

#if (0)
        if (connect(fd, p->ai_addr, p->ai_addrlen) == -1) {
            perror("server connect");
            close_sock(fd);
            continue;
        }
#endif

        break;
    }

    if (p == nullptr) {
        fprintf(stderr, "failed to connect to upstream\n");
        return -1;
    }

    inet_ntop(p->ai_family, fill_in_addr((struct sockaddr *)p->ai_addr), s, sizeof s);

    std::cout << "connection to upstream " << s << "\n";

    freeaddrinfo(servinfo);

    return fd;
}

int open_upstream(int port)
{
    return connect_by_hostname(port_map[port].first, port_map[port].second);
}

int init_libssl()
{

#if _WIN32
    WSADATA  ws_ver;
    if (WSAStartup(MAKEWORD(2, 2), &ws_ver)) {
        fprintf(stderr, "WSAStartup() fail: %d\n", GetLastError());
        return -1;
    }
#endif

    SSL_library_init();
    SSL_load_error_strings();

    return 0;
}

int init_ssl_service(ssl_session_t *session)
{
    init_port_mapping();

    init_libssl();

    session->verify_peer = false;
    session->fd = open_socket(port_map[443].second);
    connections[session->fd] = true;

    return session->fd;
}

void clean_up_ssl(ssl_session_t *sess)
{
#if (1)
    SSL_shutdown(sess->ssl);
#endif

    SSL_CTX_free(sess->ssl_old_ctx);
    SSL_CTX_free(sess->ssl_new_ctx);
    SSL_free(sess->ssl);

    sess->ssl = nullptr;

    close_sock(sess->client);
}

void clean_up(ssl_session_t *sess)
{
    clean_up_ssl(sess);

    connections.clear();
    up_connections.clear();
    down_connections.clear();
    port_map.clear();

    for (auto it = connections.begin(); it != connections.end(); ++it) {
        close_sock(it->first);
    }

#if _WIN32
    WSACleanup();
#endif
}

SSL_CTX *create_ssl_ctx(const char *sign_algo, ssl_session_t *session)
{
    SSL_CTX *ssl_ctx = nullptr;
    char file_name[512] = { 0 };

    ssl_ctx = SSL_CTX_new(SSLv23_server_method());
    if (!ssl_ctx) {
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, (void *)passwd);
    SSL_CTX_add_server_custom_ext(ssl_ctx, CUSTOM_EXT_TYPE_1000, nullptr, nullptr, nullptr, ana_ext_callback, session);

    sprintf(file_name, "server_%s.crt", sign_algo);

#if (1)
    //SSL_CTX_use_certificate_chain_file
    if (SSL_CTX_use_certificate_file(ssl_ctx, file_name, SSL_FILETYPE_PEM)
            <= 0) {
        //printf("SSL_CTX_use_certificate_file() fail");
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
#else
    X509 *x509 = load_cert(file_name);

    if (SSL_CTX_use_certificate(ssl_ctx, x509) <= 0) {
        //printf("SSL_CTX_use_certificate_file() fail");
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
    X509_free(x509);
#endif

    sprintf(file_name, "server_%s.key", sign_algo);
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, file_name, SSL_FILETYPE_PEM)
            <= 0) {
        //printf("SSL_CTX_use_PrivateKey_file() fail");
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
        //printf("Private and certificate is not matching\n");
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

#if (1)
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, nullptr);
    // we can string certs together to form a cert-chain
    sprintf(file_name, "ca_%s.crt", sign_algo);
    if (!SSL_CTX_load_verify_locations(ssl_ctx, file_name, nullptr)) {
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, nullptr);

    //SSL_CTX_set_verify_depth(ssl_ctx, 1);
    //SSL_CTX_set_tlsext_servername_callback(ssl_ctx, svr_name_callback);
#endif

    return ssl_ctx;
}

int create_ssl_context(ssl_session_t *session)
{
    session->ssl_new_ctx = create_ssl_ctx("sha2", session);
    session->ssl_old_ctx = create_ssl_ctx("sha2", session);

    return 0;
}

#if (0)
static X509 *load_cert(const char *file)
{
    X509 *x = nullptr;
    BIO *err = nullptr, *cert = nullptr;

    cert = BIO_new(BIO_s_file());
    if (cert == nullptr) {
        ERR_print_errors(err);
        goto end;
    }

    if (BIO_read_filename(cert, file) <= 0) {
        BIO_printf(err, "Error opening %s\n", file);
        ERR_print_errors(err);
        goto end;
    }

    x = PEM_read_bio_X509_AUX(cert, nullptr, nullptr, nullptr);

end:
    if (x == nullptr) {
        BIO_printf(err, "unable to load certificate\n");
        ERR_print_errors(err);
    }
    if (cert != nullptr) {
        BIO_free(cert);
    }
    return (x);
}

static int svr_name_callback(SSL *ssl, int *a, void *b)
{
    if (!ssl) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    const char *svrname = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (!svrname || svrname[0] == '\0') {
        return SSL_TLSEXT_ERR_NOACK;
    }

    /* loading certificate based on sni */
    printf("svrname:%s\n", svrname);

    return SSL_TLSEXT_ERR_OK;
}
#endif

static int ana_ext_callback(SSL *ssl, unsigned int ext_type,
                            const unsigned char *in, size_t inlen, int *al, void *arg)
{
    char ext_buf[2048] = { 0 };
    char *tag = nullptr;
    char cust_tag[1024] = { 0 };

    memcpy(ext_buf, in, inlen);

    //printf("---ext parse callback---\n");

    tag = strstr(ext_buf, "sign_algo=");
    if (tag) {
        sprintf(cust_tag, "%s", tag + strlen("sign_algo="));
    }

    printf("---cert tag [%s]----\n", cust_tag);

    ssl_session_t *session = (ssl_session_t *) arg;

    SSL_set_SSL_CTX(ssl, session->ssl_new_ctx);

    return 1;
}

#if (0)
static int cert_callback(SSL *ssl, void *a)
{

    printf("------certificate callback %p-------\n", ssl_new_ctx);

    //SSL_set_SSL_CTX(ssl, ssl_new_ctx);

#if (0)
    SSL_set_verify(ssl, SSL_CTX_get_verify_mode(ssl_new_ctx),
                   SSL_CTX_get_verify_callback(ssl_new_ctx));

    SSL_set_options(ssl, SSL_CTX_get_options(ssl_new_ctx));
#endif

    return 1;
}
#endif

#endif /* TUNS_CORE_INCLUDED_H_ */
