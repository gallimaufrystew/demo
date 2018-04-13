///
/// File:   tunc.c
/// Author: xingkanhu
///

#include "tunc_core.h"
#include "config.h"
#include "tun_socket.h"

#if __linux__
#elif _WIN32
#include "openssl\applink.c"
#endif

int event_process(fd_set *fdset, ssl_conn_t *ssl_conn, std::unordered_map<int, bool> &conns,
                  fd_desc_map_t &fd_desc_map, fd_port_map_t &fd_port_map);
int handle_client_event(int fd, ssl_conn_t *ssl_conn, fd_desc_map_t &fd_desc_map,
                        fd_port_map_t &fd_port_map, std::unordered_map<int, bool> &conns);

extern std::unordered_map<int, bool> connections;
extern config_map_t config_map;

int main(int argc, char *argv[])
{
    fd_set fdset;
    fd_desc_map_t fd_desc_map;
    fd_port_map_t fd_port_map;
    int maxls = -1;

    init_signal();

    init_listen_port();

    ssl_conn_t ssl_conn = {};
    init_ssl_config(&ssl_conn);

    init_openssl();

    auto it = config_map.equal_range("listen").first;
    for (; it != config_map.equal_range("listen").second; ++it) {
        std::cout << "listen on:" << it->second.first << "\n";
        int fd = server_open_socket(it->second.first, fd_port_map);
        maxls = std::max(maxls, fd);
        connections[fd] = true;
        fd_desc_map[fd] = "listen";
    }

    std::cout << "start handling event...\n";

    struct timeval tv;

    for (;;) {

        if (sig_exit) {
            break;
        }

        if (!ssl_conn.connected) {
            if (ssl_conn.fd > 0) {
                connections[ssl_conn.fd] = false;
                cleanup_ssl(&ssl_conn);
            }
            if (client_open_ssl(&ssl_conn) < 0) {
                continue;
            }
            connections[ssl_conn.fd] = true;
            fd_desc_map[ssl_conn.fd] = "ssl";
        }

        FD_ZERO(&fdset);

        int valid_fds = 0, maxfd = 0;

        for (auto it = connections.begin(); it != connections.end(); ++it) {
            if (it->second) {

                int       n;
                socklen_t len = sizeof(int);

                if (getsockopt(it->first, SOL_SOCKET, SO_TYPE, (char *) &n, &len) == -1) {
                    FD_CLR(it->first, &fdset);
                    close_sock(it->first);
                    connections[it->first] = false;
                    continue;
                }

                tv.tv_sec = 5;
                tv.tv_usec = 0;

                setsockopt(it->first, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));
                setsockopt(it->first, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv));
                maxfd = std::max(maxfd, it->first);
                FD_SET(it->first, &fdset);
                valid_fds ++;
            } else {
                close_sock(it->first);
            }
        }

        maxfd = std::max(maxfd, maxls);

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
            event_process(&fdset, &ssl_conn, connections, fd_desc_map, fd_port_map);
        }
    }

    fd_desc_map.clear();
    fd_port_map.clear();
    clean_up(&ssl_conn);

    return 0;
}

int event_process(fd_set *fdset, ssl_conn_t *ssl_conn,
                  std::unordered_map<int, bool> &conns, fd_desc_map_t &fd_desc_map,
                  fd_port_map_t &fd_port_map)
{
    for (auto it = conns.begin(); it != conns.end(); ++it) {

        if (it->second == false) {
            continue;
        }

        if (FD_ISSET(it->first, fdset)) {
            if (it->first == ssl_conn->fd) {
                handle_ssl_read(ssl_conn);
            } else {
                handle_client_event(it->first, ssl_conn, fd_desc_map, fd_port_map, conns);
            }
        }
    }

    return 0;
}

static int rfb_send_command(int fd, ssl_conn_t *ssl_conn, fd_desc_map_t &fd_desc_map,
                            fd_port_map_t &fd_port_map, std::unordered_map<int, bool> &conns)
{
    if (fd_port_map[fd] == 1031 || fd_port_map[fd] == 1032) {

        char rfb_cmd[] = "RFB_OPEN";
        char buf[PROTO_HEAD_SIZE + 128];

        std::memcpy(buf + 12, rfb_cmd, std::strlen(rfb_cmd));

        uint32_t len = std::strlen(rfb_cmd), nlen;
        nlen = htonl(len);
        std::memcpy(buf, &nlen, 4);

        uint32_t port = fd_port_map[fd], nport;
        nport = htonl(port);
        std::memcpy(buf + 4, &nport, 4);

        uint32_t nfd;
        nfd = htonl(fd);
        std::memcpy(buf + 8, &nfd, 4);

        int n = ssl_exact_write(ssl_conn->ssl, buf, PROTO_HEAD_SIZE + len);
        if (n != 0) {
            conns[ssl_conn->fd] = false;
        }
    }

    return 0;
}

int handle_client_event(int fd, ssl_conn_t *ssl_conn,
                        fd_desc_map_t &fd_desc_map, fd_port_map_t &fd_port_map,
                        std::unordered_map<int, bool> &conns)
{
    auto it = fd_desc_map.find(fd);
    if (it != fd_desc_map.end()) {
        if (it->second == "listen") {
            int sock = handle_accept(fd, fd_port_map);
            if (sock > 0) {
                std::cout << "accept on " << fd << " > " << sock << "\n";
                fd_desc_map[sock] = "client";
                conns[sock] = true;
                rfb_send_command(sock, ssl_conn, fd_desc_map, fd_port_map, conns);
            }
        } else {
            handle_read_client(fd, ssl_conn, fd_port_map);
        }
    }

    return 0;
}
