
#include <iostream>
#include <string>
#include <sstream>
#include <fstream>
#include <unordered_map>

extern std::unordered_map<int, std::pair<std::string, int>> port_map;

int init_port_mapping()
{
    std::ifstream ifs("tuns.conf");
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
            if (key[0] == '#') {
                continue;
            }
            port_map[std::atoi(key.c_str())] = make_pair(first, std::atoi(second.c_str()));
        }
    }
    ifs.close();

    return 0;
}
