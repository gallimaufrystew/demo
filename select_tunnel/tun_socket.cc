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

static int check_connect(int fd)
{
	for ( ;; ) {
		
		fd_set fdset;
	
		FD_ZERO(&fdset);
		FD_SET(fd, &fdset);
	
		struct timeval tv = {10, 0};
	
		int res = select(fd + 1, NULL, &fdset, NULL, &tv);
		if (res < 0 && errno != EINTR) {
			std::fprintf(stderr, "|select| %d - %s\n", errno, strerror(errno));
			return -1;
		} else if (res > 0) {
			int val;
			socklen_t len = sizeof(int);
			if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)(&val), &len) < 0) {
				std::fprintf(stderr, "|getsockopt| %d - %s\n", errno, strerror(errno));
				return -1;
			}
			if (val) {
				fprintf(stderr, "|getsockopt=| %d - %s\n", val, strerror(val));
				return -1;
			}
			break;
		}
	}

	return 0;
}

int timeout_connect(int fd, struct sockaddr *addr, socklen_t sock_len)
{
    socket_nonblock(fd);

    int res = connect(fd, addr, sock_len);
    if (res == -1) {
        int err = errno;
        if (err == EINPROGRESS || err == WSAEWOULDBLOCK || err == EAGAIN) {

			if (check_connect(fd) != 0) {
				return -1;
			}

        } else if (err == 0) {
            socket_block(fd);
            return 0;
        } else {
            std::fprintf(stderr, "|connect| %d - %s\n", errno, strerror(errno));
            return -1;
        }
    }
	
    socket_block(fd);
	
    return 0;
}

