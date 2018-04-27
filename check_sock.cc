
                int       n;
                socklen_t len = sizeof(int);

                if (getsockopt(fd_state.first, SOL_SOCKET, SO_TYPE, (char *) &n, &len) == -1) {
                    FD_CLR(fd_state.first, &fdset);
                    close_sock(fd_state.first);
                    connections[it->first] = std::make_pair(fd_state.second,false);
                    continue;
                }
