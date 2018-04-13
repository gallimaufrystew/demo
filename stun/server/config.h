
///
/// simple configuration
///

#ifndef CONFIG_H_INCLUDED
#define CONFIG_H_INCLUDED

int init_port_mapping();

#if __linux__

    extern volatile sig_atomic_t sig_exit;

#elif _WIN32

    extern volatile bool sig_exit;

    #ifdef max
        #undef max
    #endif

    #pragma warning (disable: 4996)

#endif

#endif
