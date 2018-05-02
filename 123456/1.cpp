
#include "atun_connection.h"
#include "atun_ssl.h"
#include "config.h"

static connection_list connections;

extern port_map_t port_map;
extern data_queue atun_queue;
extern up_lnk_queue_map uplnks;

int atun_event_accept(atun_event_t *ev)
{
    atun_connection_t *c = static_cast<atun_connection_t *>(ev->data);
    int client = accept(c->fd, nullptr, 0);
    if (client <= 0) {
        //atun_free_connection(c);
        return -1;
    }

    std::cout << "ssl client " << client << "\n";

    //atun_select_del_event(c->read_event, ATUN_READ_EVENT, 0);

    atun_set_nonblock(client);

    int n = atun_init_ssl_session(client);
    if (n != 0) {
        atun_close_sock(client);
        //atun_free_connection(c);
        //atun_select_del_event(c->read_event, ATUN_READ_EVENT, 0);
        std::cout << "atun_init_ssl_session\n";
        return -1;
    }

    atun_connection_t *nc = get_connection();
    if (nc == nullptr) {
        //atun_free_connection(c);
        atun_close_sock(client);
        return -1;
    }

    nc->fd = client;
    nc->read_event->accept = 0;
    nc->read_event->write = 0;
    nc->read_event->handler = atun_ssl_handshake;

    atun_select_add_event(nc->read_event, ATUN_READ_EVENT, 0);

    return 0;
}

atun_connection_t *get_connection()
{
    atun_connection_t *c = nullptr;

    if (connections.empty()) {
        return c;
    }

    c = connections.front();
    connections.pop_front();

    return c;
}

void atun_free_connection(atun_connection_t *c)
{
    connections.push_back(c);
}

void atun_init_connection(int max_connection)
{
    size_t conn_size = sizeof(atun_connection_t);
    size_t event_size = sizeof(atun_event_t);

    for (int i = 0; i < max_connection; ++i) {
        atun_connection_t *c =
            static_cast<atun_connection_t *>(atun_alloc(conn_size));
        if (c == nullptr) {
            std::cout << "atun_init_connection 1\n";
            return;
        }
        //c->buf = nullptr;
        c->read_event =
            static_cast<atun_event_t *>(atun_alloc(event_size));
        if (c->read_event == nullptr) {
            std::cout << "atun_init_connection 2\n";
            return;
        }
        c->read_event->data = c;
        c->read_event->index = ATUN_INVALID_INDEX;

        c->write_event =
            static_cast<atun_event_t *>(atun_alloc(event_size));
        if (c->write_event == nullptr) {
            std::cout << "atun_init_connection 3\n";
            return;
        }
        c->write_event->data = c;
        c->write_event->index = ATUN_INVALID_INDEX;
        connections.push_back(c);
    }
}

int atun_upstream_read(atun_event_t *ev)
{
    atun_connection_t *uc = static_cast<atun_connection_t *>(ev->data);

    ssize_t  n;
    
    u_char buf[DATA_SIZE] = {};
     
    do {
        n = recv(uc->fd, buf + PROTO_SIZE, DATA_SIZE - PROTO_SIZE, 0);

        if (n == 0) {
            return n;
        }

        if (n > 0) {
    
            std::cout <<  __func__ << " upstream size <- " << n << "\n";

            int  nlen;
            nlen = htonl(n);
            memcpy(buf, &nlen, 4);

            // now port is of no importance
            // for simplicity we omit it

            // which session ?
            // it's a tricky part

            int nsuid;
            nsuid = htonl(uc->suid);
            memcpy(buf + 8, &nsuid, 4);

            size_t size = n + PROTO_SIZE;

            std::cout <<  __func__ << " push upstream " << errno << "\n";

            u_char *data = new u_char[size];
            std::memcpy(data, buf, size);
            atun_queue.push_back(std::make_pair(data, size));
    
            return n;
        }


        if (errno == EAGAIN || errno == EINTR) {
            n = ATUN_AGAIN;
        } else {
            
            break;
        }

    } while (errno == EINTR);

    return n;
    
#if (0)
    int n = recv(uc->fd, buf + PROTO_SIZE, DATA_SIZE - PROTO_SIZE, 0);
    if (n <= 0) {
        if (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN) {
            return 0;
        }

        std::cout <<  __func__ << " fatal " << errno << "\n";

        atun_select_del_event(uc->read_event, ATUN_READ_EVENT, 0);
        atun_free_connection(uc);

        return -1;
    }
#endif

}

int atun_upstream_write(atun_event_t *ev)
{
    atun_connection_t *c = static_cast<atun_connection_t *>(ev->data);
    auto up_queue = uplnks[c->suid];
    
    if (up_queue.empty()) {
        return 0;
    }
    
    //std::cout << "fd  " << c->fd << "\n";
    
    auto item = up_queue.front();
    up_queue.pop_front();

    ssize_t n;

    for ( ;; ) {
        
        n = send(c->fd, item.first, item.second, 0);

        if (n > 0) {
            
            std::cout << "up write " << item.second << " -->> " << n << "\n";

            item.first += n;
            item.second -= n;
            
            if (item.second > 0) {
                uplnks[c->suid].push_front(item);
            }

            return n;
        }

        uplnks[c->suid].push_front(item);
        
        if (n == 0) {
            return n;
        }

        if (errno == EAGAIN || errno == EINTR) {

            if (errno == EAGAIN) {
                return ATUN_AGAIN;
            }

        } else {
            return ATUN_ERROR;
        }
    }
    
#if (0)
        int n = send(c->fd, item.first, item.second, 0);
        
        if (n == 0) {
            return n;
        }
        
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                uplnks[c->suid].push_front(item);
                //uplnks[c->suid] = up_queue;
                return 0;
            }
            
            uplnks[c->suid].push_front(item);
            // todo fatal error
            std::cout <<  __func__ << " send fatal " << strerror(errno) << "\n";
            return -1;
        }
        
        item.second -= n;
        item.first += n;
            
        if (item.second == 0) {
            return 0;
            //delete [] opos;
        }
        
        uplnks[c->suid].push_front(std::make_pair(opos, item.second));
#endif

}
