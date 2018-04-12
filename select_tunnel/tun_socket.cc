/*
 * tun_socket.cc
 */

#include "tun_socket.h"

#if __linux__

int socket_nonblock(int fd)
{
    int  nb = 1;

    return ioctl(fd, FIONBIO, &nb);
}

int socket_block(int fd)
{
    int nb = 0;

    return ioctl(fd, FIONBIO, &nb);
}

#elif _WIN32

int socket_nonblock(int fd)
{
    unsigned long  nb = 1;

    return ioctlsocket(s, FIONBIO, &nb);
}

int socket_block(int fd)
{
    unsigned long  nb = 0;

    return ioctlsocket(s, FIONBIO, &nb);
}

#endif

int timeout_connect(int fd, struct sockaddr *addr, socklen_t sock_len)
{
    socket_nonblock(fd);

    int rc = connect(fd, addr, sock_len);
    if (rc != 0) {
        if (errno == EINPROGRESS) {

            fd_set rset, wset;
            struct timeval tv = {10, 0};

            FD_ZERO(&rset);
            FD_ZERO(&wset);
            
            FD_SET(fd, &rset);
            FD_SET(fd, &wset);

            rc = select(fd + 1, &rset, &wset, NULL, &tv);
            if (rc <= 0) {
                std::fprintf(stderr, "connect ERR: %s\n", strerror(errno));
                close(fd);
                return -1;
            }

            if (rc == 1 && FD_ISSET(fd, &wset)) {
                std::cout << "connect success\n";
                socket_block(fd);
                return 0;
            } else if (rc == 2) {
                int err = 0;
                int elen = sizeof(err);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) == -1) {
                    std::fprintf(stderr, "getsockopt(SO_ERROR): %s", strerror(errno));
                    close(fd);
                    return -1;
                }
                if (err) {
                    errno = err;
                    std::fprintf(stderr, "connect ERR: %s\n", strerror(errno));
                    close(fd);
                    return -1;
                }
            }

        } 
        std::fprintf(stderr, "connect ERR: %s\n", strerror(errno));
        return -1;
    }
    socket_block(fd);
    return 0;
}
