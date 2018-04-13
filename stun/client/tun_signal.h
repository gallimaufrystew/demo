
#ifndef TUN_SIGNAL_INCLUDED_H
#define TUN_SIGNAL_INCLUDED_H

#if __linux__

#include <sys/types.h>
#include <sys/wait.h>

typedef struct {
    int sig_no;
    const char *sig_name;
    void (*handler)(int sig_no);
} signal_t;

int init_linux_signal();
void signal_handler(int sig_no);

#elif _WIN32

#include <windows.h>

BOOL WINAPI signal_handler(DWORD ctrl_type);

#else

#endif //

// common
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <signal.h>
#include <errno.h>
#include <iostream>

int init_signal();

#endif // TUNC_SIGNAL_INCLUDED_H
