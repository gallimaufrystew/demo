///
/// simple configuration
///

#ifndef CONFIG_H_INCLUDED
#define CONFIG_H_INCLUDED

#include "tun_signal.h"

#pragma warning(disable: 4996)

// msvc11 doesn't support this
// using conf_map_t = std::multimap<std::string, std::pair<int,std::string>>;

typedef std::multimap<std::string, std::pair<int, std::string>> config_map_t;

int init_listen_port();

#ifdef __linux__
    extern volatile sig_atomic_t sig_exit;
#elif _WIN32
    extern volatile bool sig_exit;
#else

#endif

#endif
