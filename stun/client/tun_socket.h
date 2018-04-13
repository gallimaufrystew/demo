/*
 * File:   tun_socket.h
 * Author: xingkanhu
 *
 * Created on April 11, 2016
 */

#ifndef TUN_SOCKET_INCLUDED_H
#define TUN_SOCKET_INCLUDED_H

#if __linux__
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <signal.h>
    #include <sys/un.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <unistd.h>
    #include <netdb.h>
#elif _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <process.h>
#endif

#pragma warning(disable: 4996)

#include <cstdio>
#include <iostream>

int socket_nonblock(int fd);
int socket_block(int fd);
int timeout_connect(int fd, struct sockaddr *addr, socklen_t sock_len);
void close_sock(int fd);

#endif /* TUN_SOCKET_INCLUDED_H */
