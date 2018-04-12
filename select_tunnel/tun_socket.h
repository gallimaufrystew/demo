
/* 
 * File:   tun_socket.h
 * Author: lfs
 *
 * Created on April 13, 2018, 1:22 AM
 */

#ifndef TUN_SOCKET_INCLUDED_H
#define TUN_SOCKET_INCLUDED_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>

int socket_nonblock(int fd);
int socket_block(int fd);
int timeout_connect(int fd, struct sockaddr* addr, socklen_t sock_len);

#endif /* TUN_SOCKET_INCLUDED_H */
