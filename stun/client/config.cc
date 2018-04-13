
#include <iostream>
#include <string>
#include <sstream>
#include <fstream>
#include <map>

#include "config.h"

extern config_map_t config_map;

int init_listen_port()
{
    std::ifstream ifs("tunc.conf");
    std::string line;

    if (ifs.is_open() == false) {
        std::cout << "configuration file doesn't exist\n";
        exit(-1);
    }

    while (std::getline(ifs, line)) {

        std::string key, first, second;
        std::istringstream is(line);
        is >> key >> first >> second;

        if (key.empty() == false) {
            std::cout << "key:" << key << " value: " << first << " " << second << "\n";
            if (key[0] == '#') {
                continue;
            }
            config_map.insert(std::make_pair(key, std::make_pair(std::atoi(first.c_str()), second)));
        }
    }
    ifs.close();

    return 0;
}
