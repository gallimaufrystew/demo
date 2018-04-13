
#ifndef TUN_SIGNAL_INCLUDED_H
#define TUN_SIGNAL_INCLUDED_H

#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>

#ifdef __linux__

    #include <sys/types.h>
    #include <sys/wait.h>

#elif _WIN32

    #include <windows.h>

#endif

#ifdef __linux__

typedef struct {
    int sig_no;
    const char *sig_name;
    void (*handler)(int sig_no);
} signal_t;

int init_signal();
void signal_handler(int sig_no);

#elif _WIN32

BOOL WINAPI signal_handler(DWORD ctrl_type);

#endif //!

int init_signal();

#endif // TUN_SIGNAL_INCLUDED_H
