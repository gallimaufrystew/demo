
#include "atun_ssl.h"

static int ana_ext_callback(SSL *ssl, unsigned int ext_type,
                            const unsigned char *in, size_t inlen, int *al, void *arg);
static SSL_CTX *create_context(const char *sign_algo);

static int atun_ssl_verify(atun_event_t *ev);
static int atun_ssl_read_head(atun_event_t *ev);
static int atun_connect_upstream(atun_event_t *ev);
static bool connection_is_new(atun_connection_t *c, int suid);
static int atun_ssl_read_body(atun_event_t *ev);
static int atun_ssl_write(atun_event_t *ev);
int atun_ssl_greed_read(atun_event_t *ev);
static void atun_ssl_clear_error();
static atun_int_t atun_handle_ssl_recv(SSL *ssl, int n);

static const char *passwd = "123456", *rfb_command = "RFB_OPEN";
static const int rfb_listen_port = 5900;

static ssl_session_t *ssl_session;

extern port_map_t port_map;
extern up_lnk_queue_map uplnks;

data_queue atun_queue;

std::list<std::pair<char *, int>> queue;
int queue_size;

void atun_init_ssl_lib()
{
    SSL_library_init();
    SSL_load_error_strings();
}

void atun_ssl_free()
{
    SSL_shutdown(ssl_session->ssl);
    SSL_CTX_free(ssl_session->old_ctx);
    SSL_CTX_free(ssl_session->new_ctx);
    SSL_free(ssl_session->ssl);
    atun_close_sock(ssl_session->fd);
}

int atun_init_ssl_session(int fd)
{
    if (ssl_session) {
        atun_ssl_free();
        atun_alloc_free(ssl_session);
        ssl_session = nullptr;
    }
    auto size = sizeof(ssl_session_t);
    ssl_session = static_cast<ssl_session_t *>(atun_alloc(size));
    if (!ssl_session) {
        atun_close_sock(ssl_session->fd);
        std::printf("atun_init_ssl_session -> atun_alloc ssl_session\n");
        return -1;
    }
    ssl_session->verify_peer = false;
    ssl_session->fd = fd;
    ssl_session->new_ctx = create_context("sha2");
    ssl_session->old_ctx = create_context("sha2");
    ssl_session->ssl = SSL_new(ssl_session->old_ctx);
    if (!ssl_session->ssl) {
        atun_alloc_free(ssl_session);
        atun_close_sock(ssl_session->fd);
        std::printf("SSL_new() fail\n");
        return -1;
    }

    SSL_set_accept_state(ssl_session->ssl);

    return 0;
}

int atun_ssl_handshake(atun_event_t *ev)
{
    atun_connection_t *c = static_cast<atun_connection_t *>(ev->data);

    SSL_set_fd(ssl_session->ssl, ssl_session->fd);

    atun_ssl_clear_error();

    int n = SSL_do_handshake(ssl_session->ssl);
    if (n <= 0) {
        ERR_print_errors_fp(stderr);
        int err = SSL_get_error(ssl_session->ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            //c->write_event->write = 1;
            //c->write_event->handler = atun_ssl_handshake;
            //atun_select_add_event(c->write_event, ATUN_WRITE_EVENT, 0);
            return 0;
        }

        atun_select_del_event(c->read_event, ATUN_READ_EVENT, 0);
        atun_free_connection(c);
        atun_ssl_free();

        //ev->handler = atun_event_accept;

        std::cout <<  __func__ << " fatal " << strerror(err) << "\n";
        return -1;
    }

    ev->handler = atun_ssl_verify;

    return 0;
}

int atun_ssl_verify(atun_event_t *ev)
{
    atun_connection_t *c = static_cast<atun_connection_t *>(ev->data);

    if (ssl_session->verify_peer) {
        X509 *cert = SSL_get_peer_certificate(ssl_session->ssl);
        if (!cert) {
            std::cout << "no peer certificate\n";
            return -1;
        }
        long ret = SSL_get_verify_result(ssl_session->ssl);
        if (ret != X509_V_OK) {
            ERR_print_errors_fp(stderr);
            return -1;
        }
        X509_free(cert);
    }

#if (0)
    //c->write_event->handler = atun_ssl_write;
    if (c->buf) {
        atun_alloc_free(c->buf);
        c->buf = nullptr;
    }

    c->left = PROTO_SIZE;
    c->buf = static_cast<u_char *>(atun_alloc(c->left));
    if (c->buf == nullptr) {
        //atun_ssl_free();
        //atun_select_del_event(c->read_event, ATUN_READ_EVENT, 0);
        //atun_free_connection(c);
        std::cout << "atun_alloc head fail\n";
        return -1;
    }
    c->last = c->buf;
#endif
    
    ev->handler = atun_ssl_greed_read;

    c->write_event->handler = atun_ssl_write;
    c->write_event->write = 1;
    c->write_event->index = ATUN_INVALID_INDEX;
    
    atun_select_add_event(c->write_event, ATUN_WRITE_EVENT, 0);

    return 0;
}

#if (0)
int process_ssl_input()
{
    int len, nlen;
    memcpy(&nlen, buf, 4);
    len = ntohl(nlen);

    int  port, nport;
    memcpy(&nport, buf + 4, 4);
    c->port = port = ntohl(nport);

    int  suid, nsuid;
    memcpy(&nsuid, buf + 8, 4);
    c->suid = suid = ntohl(nsuid);

    std::cout << "nlen " << nlen << " len " << len << "\n";
    std::cout << "nport " << nport << " port " << port << "\n";
    std::cout << "nsuid " << nsuid << " suid " << suid << "\n";
                
    if (n - PROTO_SIZE < len) {
        char *save = new char[n];
        memcpy(save, buf, n);
        queue.push_back(std::make_pair(save, n));
        return 0;
    }

    if (connection_is_new(c, suid)) {

        atun_connect_upstream(ev);

        data_queue up_queue;
        uplnks[c->suid] = up_queue;

        auto host = port_map[port];

        if (host.second == rfb_listen_port) {
            
            int left = n - PROTO_SIZE - len;
            
            if (left > 0) {
                char *save = new char[left];
                memcpy(save, buf + PROTO_SIZE + len, left);
                queue.push_back(std::make_pair(save, left));
            }
            return 0;
        }
    }

    u_char *copy = new u_char[len], *last = copy;
    std::memcpy(copy, buf + PROTO_SIZE, len);
    size_t size = len;
    uplnks[suid].push_back(std::make_pair(copy, size));

    int left = all_size - PROTO_SIZE - len;
    if (left > 0) {
        
        queue.clear();
    
        char *save = new char[left];
        memcpy(save, sdata + PROTO_SIZE + len, left);
        queue.push_back(std::make_pair(save, left));
    }

    delete [] osave;    
}
#endif

static void
atun_ssl_clear_error()
{
    while (ERR_peek_error()) {
    }

    ERR_clear_error();
}

ssize_t atun_ssl_read(char *buf, size_t size) {

    int  n, bytes;
        
    bytes = 0;

    atun_ssl_clear_error();

    /*
     * SSL_read() may return data in parts, so try to read
     * until SSL_read() would return no data
     */

    for ( ;; ) {

        n = SSL_read(ssl_session->ssl, buf, size);
        if (n > 0) {
            bytes += n;
        }

        int last = atun_handle_ssl_recv(ssl_session->ssl, n);
        if (last == ATUN_OK) {

            size -= n;

            if (size == 0) {
                return bytes;
            }

            buf += n;

            continue;
        }

        if (bytes) {
            return bytes;
        }

        switch (last) {
        case ATUN_DONE:
            return 0;
        case ATUN_ERROR:
            /* fall through */
        case ATUN_AGAIN:
            return last;
        }
    }
}

#if (0)
int atun_ssl_greed_read(atun_event_t *ev)
{
    char buf[81920] = {};
    int size = 81920;
    
    atun_connection_t *c = static_cast<atun_connection_t *>(ev->data);

    int n = atun_ssl_read(buf,size);
    if (n <= 0) {
        if (n == ATUN_AGAIN) {
            return 0;
        }
        atun_select_del_event(c->read_event, ATUN_READ_EVENT, 0);
        atun_ssl_free();
        atun_free_connection(c);
        return -1;
    }

    std::cout << "ssl read ... " << n << "\n";

    char *save = new char[n];
    memcpy(save, buf, n);
    queue.push_back(std::make_pair(save,n));
    queue_size += n;
    
    process_ssl_input();

    return 0;
    
}
#endif

#if (1)

int atun_ssl_greed_read(atun_event_t *ev)
{
    atun_connection_t *c = static_cast<atun_connection_t *>(ev->data);

    char buf[8192] = {};
    ssize_t size = 8192;
    
    int n = atun_ssl_read(buf, 8192);
    
    std::cout << "atun_ssl_read -> " << n << "\n";
    
    if (n <= 0) {
        if (n == ATUN_AGAIN) {
            return 0;
        }
        ///atun_select_del_event(c->read_event, ATUN_READ_EVENT, 0);
        ///atun_ssl_free();
        ///atun_free_connection(c);
        return -1;
    }
    
    char *save = new char[n];
    memcpy(save, buf, n);
    queue.push_back(std::make_pair(save, n));
    
    int all_size = 0;

    for (auto it = queue.begin(); it != queue.end(); ++it) {
        all_size += it->second;
    }

    std::cout << "all_size ... " << all_size << "\n";
    
    if (all_size <= PROTO_SIZE) {
        return 0;
    }

    char *ssl_data = new char[all_size], *osave = ssl_data;

    for (auto it = queue.begin(); it != queue.end(); ++it) {
        memcpy(ssl_data, it->first, it->second);
        ssl_data += it->second;
        delete [] it->first;
    }
    
    queue.clear();
    
    ssl_data = osave;
    
    int len, nlen;
    memcpy(&nlen, ssl_data, 4);
    len = ntohl(nlen);

    int  port, nport;
    memcpy(&nport, ssl_data + 4, 4);
    c->port = port = ntohl(nport);

    int  suid, nsuid;
    memcpy(&nsuid, ssl_data + 8, 4);
    c->suid = suid = ntohl(nsuid);

    std::cout << "nlen " << nlen << " len " << len << "\n";
    std::cout << "nport " << nport << " port " << port << "\n";
    std::cout << "nsuid " << nsuid << " suid " << suid << "\n";
                
    if (all_size - PROTO_SIZE < len) {
        //char *save = new char[all_size];
        //memcpy(save, sdata, all_size);
        queue.push_back(std::make_pair(ssl_data, all_size));
        //delete [] osave;
        return 0;
    }

    if (connection_is_new(c, suid)) {

        atun_connect_upstream(ev);

        data_queue up_queue;
        uplnks[c->suid] = up_queue;

        auto host = port_map[port];

        if (host.second == rfb_listen_port) {
            
            int left = all_size - PROTO_SIZE - len;
            
            if (left > 0) {
                char *save = new char[left];
                memcpy(save, ssl_data + PROTO_SIZE + len, left);
                queue.push_front(std::make_pair(save, left));
                delete [] ssl_data;
            }

            return 0;
        }
    }   

    u_char *up_data = new u_char[len];
    std::memcpy(up_data, ssl_data + PROTO_SIZE, len);
    size_t up_size = len;
    uplnks[suid].push_back(std::make_pair(up_data, up_size));

    int left = all_size - PROTO_SIZE - len;
    if (left > 0) {
        char *save = new char[left];
        memcpy(save, ssl_data + PROTO_SIZE + len, left);
        queue.push_front(std::make_pair(save, left));
    }

    delete [] ssl_data;

    return 0;
}

#endif

bool connection_is_new(atun_connection_t *c, int suid)
{
    auto it = uplnks.find(suid);
    if (it == std::end(uplnks)) {
        return true;
    }
    return false;
}

static atun_int_t
atun_handle_ssl_recv(SSL *ssl, int n)
{
    int         sslerr;
    atun_err_t  err;

    if (n > 0) {
        return ATUN_OK;
    }

    sslerr = SSL_get_error(ssl, n);

    err = (sslerr == SSL_ERROR_SYSCALL) ? atun_errno : 0;

    if (sslerr == SSL_ERROR_WANT_READ) {
        return ATUN_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_WRITE) {
        std::printf("peer started SSL renegotiation");
        return ATUN_AGAIN;
    }

    if (sslerr == SSL_ERROR_ZERO_RETURN || ERR_peek_error() == 0) {
        std::printf("peer shutdown SSL cleanly");
        return ATUN_DONE;
    }

    std::printf("SSL_read() failed");

    return ATUN_ERROR;
}

#if (0)
int atun_ssl_read_head(atun_event_t *ev)
{
    atun_connection_t *c = static_cast<atun_connection_t *>(ev->data);

    atun_ssl_clear_error();

    int n = SSL_read(ssl_session->ssl, c->last, c->left);
    if (n <= 0) {
        int err = SSL_get_error(ssl_session->ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            return 0;
        }
        atun_select_del_event(c->read_event, ATUN_READ_EVENT, 0);
        atun_ssl_free();
        atun_free_connection(c);
        std::cout <<  __func__ << "atun_ssl_read_head -> " << strerror(err) << "\n";
        return -1;
    }

    c->left -= n;
    c->last += n;

    if (c->left == 0) {

        std::cout <<  __func__ << " 111111111111111 \n";

        uint32_t  nlen;
        memcpy(&nlen, c->buf, 4);
        c->left = ntohl(nlen);

        uint32_t  nport;
        memcpy(&nport, c->buf + 4, 4);
        c->port = ntohl(nport);

        uint32_t  suid, nsuid;
        memcpy(&nsuid, c->buf + 8, 4);
        c->suid = suid = ntohl(nsuid);

        if (c->buf) {
            atun_alloc_free(c->buf);
            c->buf = nullptr;
        }

        std::cout <<  __func__ << " left " << c->left << "\n";

        c->buf = static_cast<u_char *>(atun_alloc(c->left));
        if (c->buf == nullptr) {
            //atun_select_del_event(c->read_event, ATUN_READ_EVENT, 0);
            //atun_ssl_free();
            //atun_free_connection(c);
            std::cout << "atun_ssl_read_head -> atun_alloc body fail\n";
            return -1;
        }

        std::cout <<  __func__ << " fffffffffff " << c->left << "\n";

        c->last = c->buf;
        ev->handler = atun_ssl_read_body;



        //else {

        //c->read_event->handler = atun_ssl_read_body;
        //}
    }

    atun_ssl_read_body(ev);

    c->write_event->handler = atun_ssl_write;
    c->write_event->index = ATUN_INVALID_INDEX;
    atun_select_add_event(c->write_event, ATUN_WRITE_EVENT, 0);

    std::cout <<  __func__ << " ok \n";

    return 0;
}

int atun_ssl_read_body(atun_event_t *ev)
{
    atun_connection_t *c = static_cast<atun_connection_t *>(ev->data);

    std::cout <<  __func__ << "  xxxxxxxx " << c->left << "\n";

    atun_ssl_clear_error();

    std::cout <<  __func__ << "  left " << c->left << "\n";

    int n = SSL_read(ssl_session->ssl, c->last, c->left);
    if (n <= 0) {
        int err = SSL_get_error(ssl_session->ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            return 0;
        }
        atun_select_del_event(c->read_event, ATUN_READ_EVENT, 0);
        atun_ssl_free();
        atun_free_connection(c);
        std::cout <<  __func__ << " -> " << strerror(err) << "\n";
        return -1;
    }

    c->left -= n;
    c->last += n;

    if (c->left == 0) {

        auto host = port_map[c->port];

        std::cout <<  __func__ << "  222222222 \n";

        if (connection_is_new(c, c->suid)) {

            atun_connect_upstream(ev);

            data_queue queue;
            uplnks[c->suid] = queue;

            if (host.second == rfb_listen_port) {

                std::cout <<  __func__ << "  33333333 \n";

                c->left = PROTO_SIZE;
                c->buf = static_cast<u_char *>(atun_alloc(PROTO_SIZE));
                if (c->buf == nullptr) {
                    //atun_select_del_event(c->read_event, ATUN_READ_EVENT, 0);
                    //atun_ssl_free();
                    //atun_free_connection(c);
                    std::cout << "atun_ssl_read_body -> atun_alloc head fail\n";
                    return -1;
                }
                c->last = c->buf;
                ev->handler = atun_ssl_read_head;

                return 0;
            }
        }

        std::cout <<  __func__ << "  55555555555 \n";
        /*
        if (host.second == rfb_listen_port &&
            memcmp(c->buf, rfb_command, std::strlen(rfb_command)) == 0) {
            return 0;
        }*/

        size_t size = c->last - c->buf;
        u_char *data = static_cast<u_char *>(atun_alloc(size)), *last = data;
        std::memcpy(data, c->buf, size);
        //atun_connection_t *up = c->uplnks[c->suid];
        uplnks[c->suid].push_back(std::make_pair(last, size));


        atun_alloc_free(c->buf);

        c->left = PROTO_SIZE;
        c->buf = static_cast<u_char *>(atun_alloc(PROTO_SIZE));
        if (c->buf == nullptr) {
            //atun_select_del_event(c->read_event, ATUN_READ_EVENT, 0);
            //atun_ssl_free();
            //atun_free_connection(c);
            std::cout << "atun_ssl_read_body -> atun_alloc head fail\n";
            return -1;
        }
        c->last = c->buf;
        ev->handler = atun_ssl_read_head;
    }

    return 0;
}
#endif

int atun_ssl_write(atun_event_t *ev)
{
    atun_connection_t *c = static_cast<atun_connection_t *>(ev->data);

    if (atun_queue.empty()) {
        return 0;
    }
    
        atun_ssl_clear_error();
        
        auto item = atun_queue.front();
        atun_queue.pop_front();
        
        auto n = SSL_write(ssl_session->ssl, item.first, item.second);
        
        std::cout << "ssl write <<-- " << n << "\n";
        
        if (n > 0) {
            
            item.second -= n;
            item.first += n;
            
            if (item.second > 0) {
                atun_queue.push_front(item);
            }
            
            return n;
        }
        

    int sslerr = SSL_get_error(ssl_session->ssl, n);

    int err = (sslerr == SSL_ERROR_SYSCALL) ? errno : 0;

    if (sslerr == SSL_ERROR_WANT_WRITE) {
        return ATUN_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_READ) {
        return ATUN_AGAIN;
    }

    return ATUN_ERROR;
}

int atun_connect_upstream(atun_event_t *ev)
{
    atun_connection_t *c = static_cast<atun_connection_t *>(ev->data);

    auto host = port_map[c->port];

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(host.second);
    
    std::cout << "backend.... " << host.first << "\n";
    
    if (valid_ip(host.first, addr)) {
        
        std::cout << "connect by ip...\n";
        
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            std::printf("socket() ERR");
            return -1;
        }
        if (connect_backend(fd, (sockaddr*)&addr, sizeof(addr))) {
            //perror("server connect");
            atun_close_sock(fd);
            return -1;
        }
        return fd;
    }

    int n = async_connect(host.first, host.second);
    if (n <= 0) {
        std::cout << "async_connect_upstream fail" << "\n";
        //atun_select_del_event(c->read_event, ATUN_READ_EVENT, 0);
        //atun_ssl_free();
        //atun_free_connection(c);
        return -1;
    }

    std::cout << "up fd " << n << "\n";

    atun_set_nonblock(n);

    atun_connection_t *uc = get_connection();
    if (uc == nullptr) {
        std::cout << "async_connect_upstream -> get_connection fail" << "\n";
        //atun_select_del_event(c->read_event, ATUN_READ_EVENT, 0);
        //atun_ssl_free();
        //atun_free_connection(c);
        return -1;
    }

    uc->fd = n;
    atun_event_t *rev = uc->read_event;
    atun_event_t *wev = uc->write_event;

    //uc->down = c;
    uc->suid = c->suid;

    rev->index = ATUN_INVALID_INDEX;
    rev->write = 0;
    rev->handler = atun_upstream_read;
    
    atun_select_add_event(rev, ATUN_READ_EVENT, 0);

    wev->index = ATUN_INVALID_INDEX;
    wev->write = 1;
    wev->handler = atun_upstream_write;
    
    atun_select_add_event(wev, ATUN_WRITE_EVENT, 0);

    //ev->handler = atun_ssl_read_body;

    return 0;
}

static SSL_CTX *create_context(const char *sign_algo)
{
    SSL_CTX *ctx = nullptr;
    char file_name[512] = {0};

    ctx = SSL_CTX_new(SSLv23_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    //SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_default_passwd_cb_userdata(ctx, (void *) passwd);
    SSL_CTX_add_server_custom_ext(ctx, CUSTOM_EXT_TYPE_1000,
                                  nullptr, nullptr, nullptr, ana_ext_callback, ssl_session);

    sprintf(file_name, "server_%s.crt", sign_algo);

#if (1)
    //SSL_CTX_use_certificate_chain_file
    if (SSL_CTX_use_certificate_file(ctx, file_name, SSL_FILETYPE_PEM)
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
    if (SSL_CTX_use_PrivateKey_file(ctx, file_name, SSL_FILETYPE_PEM)
            <= 0) {
        //printf("SSL_CTX_use_PrivateKey_file() fail");
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    if (SSL_CTX_check_private_key(ctx) != 1) {
        //printf("Private and certificate is not matching\n");
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

#if (1)
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    // we can string certs together to form a cert-chain
    sprintf(file_name, "ca_%s.crt", sign_algo);
    if (!SSL_CTX_load_verify_locations(ctx, file_name, nullptr)) {
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);

    //SSL_CTX_set_verify_depth(ctx, 1);
    //SSL_CTX_set_tlsext_servername_callback(ctx, svr_name_callback);
#endif

    return ctx;
}

static int ana_ext_callback(SSL *ssl, unsigned int ext_type,
                            const unsigned char *in, size_t inlen, int *al, void *arg)
{
    char ext_buf[2048] = {0};
    char *tag = nullptr;
    char cust_tag[1024] = {0};

    std::memcpy(ext_buf, in, inlen);

    //printf("---ext parse callback---\n");

    tag = strstr(ext_buf, "sign_algo=");
    if (tag) {
        sprintf(cust_tag, "%s", tag + strlen("sign_algo="));
    }

    printf("---cert tag [%s]----\n", cust_tag);

    ssl_session_t *session = (ssl_session_t *) arg;

    SSL_set_SSL_CTX(ssl, session->new_ctx);

    return 1;
}
