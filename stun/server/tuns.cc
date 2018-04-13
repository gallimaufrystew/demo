///
/// File:   tuns.c
/// Author: xingkanhu
///

#include "tun_signal.h"
#include "tuns_core.h"
#include "config.h"

#if _WIN32
#include "openssl\applink.c"
#endif

int event_process(fd_set *fdset, std::unordered_map<int, bool> &conns, ssl_session_t *ssl_session);
int handle_read_ssl_client(std::unordered_map<int, bool> &conns, ssl_session_t *ssl_session);
int handle_ssl_accept_event(std::unordered_map<int, bool> &conns, ssl_session_t *ssl_session);
int event_process_init(fd_set *rset, int &maxfd);

extern std::unordered_map<int, bool> connections;

int main(int argc, char *argv[])
{
    fd_set fdset;
    struct timeval tv = {};

    init_signal();

    ssl_session_t ssl_session = {};

    init_ssl_service(&ssl_session);

    std::cout << "ssl fd " << ssl_session.fd << "\n";

    std::cout << "start handling event...\n";

    for (;;) {

        if (sig_exit) {
            break;
        }

        int valid_fds = 0, maxfd = 0;
        valid_fds = event_process_init(&fdset, maxfd);
        if (valid_fds <= 0) {
            waste_time(1000);
            continue;
        }

        tv.tv_sec = 1000;
        tv.tv_usec = 0;

        int ret = select(maxfd + 1, &fdset, nullptr, nullptr, &tv);
        if (ret == 0) {
            std::cout << "no active event\n";
        } else if (ret < 0) {
            std::cout << "select ERR: " << strerror(errno) << "\n";
        } else {
            event_process(&fdset, connections, &ssl_session);
        }
    }

    clean_up(&ssl_session);

    return 0;
}

int event_process_init(fd_set *rset, int &maxfd)
{
    int valid_fds = 0;

    FD_ZERO(rset);

    for (auto it = connections.begin(); it != connections.end(); ++it) {

        if (it->second == false) {
            close_sock(it->first);
            continue;
        }

        socklen_t len;
        int       val;

        if (getsockopt(it->first, SOL_SOCKET, SO_TYPE, &val, &len) == -1) {
            FD_CLR(it->first, rset);
            connections[it->first] = false;
            close_sock(it->first);
            continue;
        }

        struct timeval tv = {5, 0};
        setsockopt(it->first, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));
        setsockopt(it->first, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv));
        maxfd = std::max(maxfd, it->first);
        FD_SET(it->first, rset);
        valid_fds ++;
    }
    return valid_fds;
}

int event_process(fd_set *fdset, std::unordered_map<int, bool> &conns, ssl_session_t *ssl_session)
{
    for (auto it = conns.begin(); it != conns.end(); ++it) {

        if (it->second == false) {
            continue;
        }

        if (FD_ISSET(it->first, fdset)) {
            if (it->first == ssl_session->fd) {
                handle_ssl_accept_event(conns, ssl_session);
            } else if (it->first == ssl_session->client) {
                handle_read_ssl_client(conns, ssl_session);
            } else {
                handle_upstream_read(it->first, ssl_session);
            }
        }
    }

    return 0;
}

int handle_ssl_accept_event(std::unordered_map<int, bool> &conns, ssl_session_t *ssl_session)
{
    /// we always accept new ssl connection
    /// but we destroy previously established
    // thus we keep only one ssl connection
    if (ssl_session->client > 0) {
        // cleanup previously claimed resources
        clean_up_ssl(ssl_session);
    }

    handle_ssl_accept_client(ssl_session);
    conns[ssl_session->client] = true;

#if (0)
    if (!ssl_session->connected) {

        if (ssl_session->client > 0) {
            // cleanup previously claimed resources
            clean_up_ssl(ssl_session);
        }

        handle_ssl_accept_client(ssl_session);
        conns[ssl_session->client] = true;

    } else {
        // only one
        int fd = accept(ssl_session->fd, nullptr, 0);
        if (fd > 0) {
            close(fd);
        }
    }
#endif
    return 0;
}

int handle_read_ssl_client(std::unordered_map<int, bool> &conns, ssl_session_t *ssl_session)
{
    return handle_ssl_read(ssl_session);
}
