///
/// help function
///

#include "tunc_core.h"
#include "config.h"
#include "tun_socket.h"

static const char cust_str[] = "sign_algo=sha2";
static SSL_CTX *create_ssl_ctx(const char *sign_algo, ssl_conn_t *ssl_con);
static int add_cust_ext_callback(SSL *s, unsigned int ext_type,
                                 const unsigned char **out, size_t *outlen,
                                 int *al, void *arg);
static int client_open_socket(std::string &host, int port);

std::unordered_map<int, bool> connections;
config_map_t config_map;

int exact_write(int fd, void *buf, int len)
{
    int    bytes_left, written_bytes;
    char  *ptr = static_cast<char *>(buf);

    bytes_left = len;

    while (bytes_left > 0) {
        written_bytes = send(fd, ptr, bytes_left, 0);
        if (written_bytes <= 0) {
            if (errno == EINTR) {
                written_bytes = 0;
            } else if (errno == EWOULDBLOCK || errno == EAGAIN) {
                written_bytes = 0;
            } else {
                // fatal error
                return -1;
            }
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

    bytes_left = len;
    
    if (ssl == nullptr) {
        return -1;
    }

    while (bytes_left > 0) {
        bytes_read = SSL_read(ssl, ptr, bytes_left);
        if (bytes_read <= 0) {

#if (0)
            return -1;

#elif (1)
            int err = SSL_get_error(ssl, bytes_read);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                bytes_read = 0;
            } else {
                // todo fatal error
                return -1;
            }
#endif
        }
        bytes_left -= bytes_read;
        ptr += bytes_read;
    }
    return 0;
}

int ssl_exact_write(SSL *ssl, void *buf, int len)
{
    int    bytes_left, written_bytes;
    char  *ptr = static_cast<char*>(buf);

    bytes_left = len;
    
    if (ssl == nullptr) {
        return -1;
    }

    while (bytes_left > 0) {
        written_bytes = SSL_write(ssl, ptr, bytes_left);
        if (written_bytes <= 0) {

#if (0)
            return -1;

#elif (1)
            int err = SSL_get_error(ssl, written_bytes);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                written_bytes = 0;
            } else {
                // todo fatal error
                return -1;
            }
#endif

        }
        bytes_left -= written_bytes;
        ptr += written_bytes;
    }

    return 0;
}

int handle_accept(int fd, fd_port_map_t &port_map)
{
#if  (1)
    fd_set rset;
    struct timeval tv = {5, 0};

    FD_ZERO(&rset);
    FD_SET(fd, &rset);

    int ret = select(fd + 1, &rset, nullptr, nullptr, &tv);
    if (ret > 0) {
        int client = accept(fd, nullptr, 0);
        if (client > 0) {
            port_map[client] = port_map[fd];
        }
        return client;
    }
    return -1;
#elif (0)
    int client = accept(fd, nullptr, 0);
    if (client > 0) {
        port_map[client] = port_map[fd];
    }
    return client;
#endif
}

int handle_ssl_read(ssl_conn_t *ssl_con)
{
    char buf[PROTO_HEAD_SIZE + USER_MSG_SIZE] = {0};

    int ret = ssl_exact_read(ssl_con->ssl, buf, PROTO_HEAD_SIZE);
    if (ret != 0) {
        ssl_con->connected = false;
        return -1;
    }

    uint32_t len, nlen;
    std::memcpy(&nlen, buf, 4);
    len = ntohl(nlen);

    uint32_t port, nport;
    std::memcpy(&nport, buf + 4, 4);
    port = ntohl(nport);

    uint32_t fd, nfd;
    std::memcpy(&nfd, buf + 8, 4);
    fd = ntohl(nfd);

    std::cout << "ssl data size <--- " << len << "\n";

    ret = ssl_exact_read(ssl_con->ssl, buf + PROTO_HEAD_SIZE, len);
    if (ret != 0) {
        ssl_con->connected = false;
        return -1;
    }

    ret = exact_write(fd, buf + PROTO_HEAD_SIZE, len);
    if (ret != 0) {
        connections[fd] = false;
    }

    return 0;
}

int handle_read_client(int fd, ssl_conn_t *ssl_con,
                       fd_port_map_t &port_map)
{
    char buf[PROTO_HEAD_SIZE + USER_MSG_SIZE] = {0};

    int ret = recv(fd, buf + PROTO_HEAD_SIZE, USER_MSG_SIZE, 0);
    if (ret <= 0) {
        if (errno == EINTR) {
            return ret;
        } else if (errno == EWOULDBLOCK || errno == EAGAIN) {
            return ret;
        } else {
            connections[fd] = false;
        }
        return ret;
    }

    std::cout << "client data size ---> " << ret << "\n";

    uint32_t len = ret, nlen;
    nlen = htonl(len);
    std::memcpy(buf, &nlen, 4);

    uint32_t port = port_map[fd], nport;
    nport = htonl(port);
    std::memcpy(buf + 4, &nport, 4);

    uint32_t nfd;
    nfd = htonl(fd);
    std::memcpy(buf + 8, &nfd, 4);

    int n = ssl_exact_write(ssl_con->ssl, buf, ret + PROTO_HEAD_SIZE);
    if (n != 0) {
        std::cout << "ssl_exact_write() ERR\n";
        ssl_con->connected = false;
        return -1;
    }

    return 0;
}

void init_openssl()
{

#if _WIN32
    WSADATA  ws_ver;
    if (WSAStartup(MAKEWORD(2, 2), &ws_ver)) {
        std::fprintf(stderr, "WSAStartup() ERR: %d\n", GetLastError());
        exit(2);
    }
#endif

    SSL_library_init();
    SSL_load_error_strings();

    OpenSSL_add_all_algorithms();
}

void cleanup_ssl(ssl_conn_t *ssl_conn)
{
    SSL_shutdown(ssl_conn->ssl);
    SSL_CTX_free(ssl_conn->ssl_ctx);
    SSL_free(ssl_conn->ssl);

    close_sock(ssl_conn->fd);
}

void clean_up(ssl_conn_t *ssl_conn)
{
    cleanup_ssl(ssl_conn);

    connections.clear();
    config_map.clear();

    for (auto it = connections.begin(); it != connections.end(); ++it) {
        if (it->second) {
            close_sock(it->first);
        }
    }

#if _WIN32
    WSACleanup();
#endif

}

int init_ssl_config(ssl_conn_t *ssl_config)
{
    ssl_config->verify_peer = true;
    auto it = config_map.find("ssl");
    if (it != config_map.end()) {
        ssl_config->ssl_host = it->second.second;
        ssl_config->ssl_port = it->second.first;
    } else {
        std::cout << "no ssl configuration\n";
        return -1;
    }

    return 0;
}

int server_open_socket(int port, fd_port_map_t &port_map)
{
    int fd;
    struct sockaddr_in addr = {};

    //memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        std::printf("socket() ERR");
        exit(EXIT_FAILURE);
    }

    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(int));

    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        std::printf("bind() ERR");
        exit(EXIT_FAILURE);
    }

    if (listen(fd, 5) < 0) {
        std::printf("listen() ERR");
        exit(EXIT_FAILURE);
    }

    port_map[fd] = port;

    return fd;
}

void waste_time(uint32_t seconds)
{
#if __linux__
    sleep(seconds);
#elif _WIN32
    Sleep(seconds);
#endif
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
    struct addrinfo hints = {}, *servinfo, *p;
    char  s[INET6_ADDRSTRLEN];

    //memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;// AF_UNSPEC AF_INET6
    hints.ai_socktype = SOCK_STREAM;

    char service[128] = {0};
    //std::string service;
    std::sprintf(service, "%d", port);

    if ((rv = getaddrinfo(host.c_str(), service, &hints, &servinfo)) != 0) {
        fprintf(stderr, "client getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    for (p = servinfo; p != nullptr; p = p->ai_next) {

        if ((fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            std::fprintf(stderr, "ssl client socket\n");
            continue;
        }

        if (timeout_connect(fd, p->ai_addr, p->ai_addrlen) != 0) {
            std::fprintf(stderr, "timeout_connect() ERR\n");
            close_sock(fd);
            continue;
        }

#if (0)
        if (connect(fd, p->ai_addr, p->ai_addrlen) == -1) {
            perror("ssl connect");
            close_sock(fd);
            continue;
        }
#endif

        break;
    }

    if (p == nullptr) {
        fprintf(stderr, "fail to connect to ssl server\n");
        return -1;
    }

    inet_ntop(p->ai_family, fill_in_addr((struct sockaddr *)p->ai_addr), s, sizeof s);
    std::cout << "connection to ssl server: " << s << "\n";

    freeaddrinfo(servinfo);

    return fd;
}

static int client_open_socket(std::string &host, int port)
{
    return connect_by_hostname(host, port);
}

static int add_cust_ext_callback(SSL *s, unsigned int ext_type,
                                 const unsigned char **out,
                                 size_t *outlen, int *al, void *arg)
{
    *out = (const unsigned char *) cust_str;
    *outlen = std::strlen(cust_str);

    return 1;
}

int client_open_ssl(ssl_conn_t *ssl_con)
{
    ssl_con->fd = client_open_socket(ssl_con->ssl_host, ssl_con->ssl_port);
    if (ssl_con->fd <= 0) {
        return -1;
    }

    //struct timeval tv = {5, 0};
    //setsockopt(ssl_con->fd, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));
    //setsockopt(ssl_con->fd, SOL_SOCKET, SO_SNDTIMEO, (char*)&tv, sizeof(tv));

    ssl_con->ssl_ctx = create_ssl_ctx("sha2", ssl_con);

    //SSL_CTX_set_mode(ssl_con->ssl_ctx, SSL_MODE_AUTO_RETRY);

    ssl_con->ssl = SSL_new(ssl_con->ssl_ctx);
    if (!ssl_con->ssl) {
        printf("SSL_new() failed\n");
        return -1;
    }
    SSL_set_fd(ssl_con->ssl, ssl_con->fd);

    //std::cout << "SSL_connect-->\n";

    int ret = SSL_connect(ssl_con->ssl);
    if (ret != 1) {
        //ERR_print_errors_fp(stderr);
        printf("SSL_connect ERR: %d %s\n", SSL_get_error(ssl_con->ssl, ret), strerror(errno));
        return -1;
    }

    std::cout << "verify_peer\n";

    if (ssl_con->verify_peer) {
        X509 *cert = SSL_get_peer_certificate(ssl_con->ssl);
        if (cert) {
            long ret = SSL_get_verify_result(ssl_con->ssl);
            if (ret != X509_V_OK) {
                std::printf("verify ERR\n");
                goto fail;
            }
            X509_free(cert);
        } else {
            goto fail;
        }
    }

    std::cout << "verify ok\n";

    ssl_con->connected = true;

    return ssl_con->fd;

fail:

    cleanup_ssl(ssl_con);

    return -1;
}

static SSL_CTX *create_ssl_ctx(const char *sign_algo,
                               ssl_conn_t *ssl_con)
{
    ssl_con->ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ssl_con->ssl_ctx) {
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    SSL_CTX_add_client_custom_ext(ssl_con->ssl_ctx, CUSTOM_EXT_TYPE_1000,
                                  add_cust_ext_callback,
                                  nullptr, nullptr,
                                  nullptr, nullptr);

    char file_name[512] = {0};
    //std::string file_name;
    std::sprintf(file_name, "client_%s.crt", sign_algo);

#if (0)
#if (1)
    //SSL_CTX_use_certificate_file SSL_FILETYPE_PEM
    if (SSL_CTX_use_certificate_file(ssl_con->ssl_ctx, file_name,
                                     SSL_FILETYPE_PEM) <= 0) {
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

    std::sprintf(file_name, "client_%s.key", sign_algo);
    if (SSL_CTX_use_PrivateKey_file(ssl_con->ssl_ctx, file_name,
                                    SSL_FILETYPE_PEM) <= 0) {
        //printf("SSL_CTX_use_PrivateKey_file() fail");
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    if (SSL_CTX_check_private_key(ssl_con->ssl_ctx) != 1) {
        //printf("Private and certificate is not matching\n");
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
#endif

    // we can string certs together to form a cert-chain
    std::sprintf(file_name, "ca_%s.crt", sign_algo);
    if (!SSL_CTX_load_verify_locations(ssl_con->ssl_ctx, file_name, nullptr)) {
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
    SSL_CTX_set_verify(ssl_con->ssl_ctx, SSL_VERIFY_PEER, nullptr);
    //SSL_CTX_set_verify_depth(ssl_ctx, 1);
    //SSL_CTX_set_tlsext_servername_callback(ssl_ctx, svr_name_callback);

    return ssl_con->ssl_ctx;
}
