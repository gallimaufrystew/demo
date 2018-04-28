
    if (is_new_connection(suid)) {
        int up_fd = open_upstream(port);
        if (up_fd <= 0) {
            return -1;
        }

        std::cout << "new upstream " << up_fd << "\n";
        connections[suid] = std::make_pair(up_fd, true);
        fd2uid[up_fd] = suid;
        if (if (port_map[port].second == rfb_listen_port)) {
            return up_fd;
        }
    }
    
    auto fd_state = connections[suid];
    int ret = exact_write(fd_state.first, buf + PROTO_HEAD_SIZE, len);
    if (ret != 0) {
       connections[suid] = std::make_pair(fd_state.first, false);
    }
    return ret;
