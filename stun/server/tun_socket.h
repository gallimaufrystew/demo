/*
 * File:   tun_socket.h
 * Author: xinkanhu
 *
 * Created on April 11, 2018
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
#include <cstdio>
#include <iostream>

int socket_nonblock(int fd);
int socket_block(int fd);
// it takes too long for connect to timeout
// so we have this nonblocking version
int timeout_connect(int fd, struct sockaddr *addr, socklen_t sock_len);

#endif /* TUN_SOCKET_INCLUDED_H */
