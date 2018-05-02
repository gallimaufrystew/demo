
#include "atun_select.h"
#include "atun_mem.h"

static fd_set         master_read_fd_set;
static fd_set         master_write_fd_set;
static fd_set         work_read_fd_set;
static fd_set         work_write_fd_set;

static atun_int_t      max_fd;
static atun_uint_t     nevents;

static atun_event_t  **event_index;

static void
atun_select_repair_fd_sets();

atun_int_t
atun_select_init()
{
    //atun_event_t  **index;

    //if (event_index == NULL) {

    FD_ZERO(&master_read_fd_set);
    FD_ZERO(&master_write_fd_set);

    nevents = 0;

    //}

    size_t event_nums = sizeof(atun_event_t *) * 2 * MAX_CONNECTIONS;

    event_index = static_cast<atun_event_t **>(atun_alloc(event_nums));
    if (event_index == nullptr) {
        return ATUN_ERROR;
    }
    /*
        if (atun_process >= NGX_PROCESS_WORKER
            || cycle->old_cycle == NULL
            || cycle->old_cycle->connection_n < cycle->connection_n)
        {
            index = atun_alloc(sizeof(atun_event_t *) * 2 * cycle->connection_n,
                              cycle->log);
            if (index == NULL) {
                return NGX_ERROR;
            }

            if (event_index) {
                atun_memcpy(index, event_index, sizeof(atun_event_t *) * nevents);
                atun_free(event_index);
            }

            event_index = index;
        }

        atun_io = atun_os_io;

        atun_event_actions = atun_select_module_ctx.actions;

        atun_event_flags = NGX_USE_LEVEL_EVENT;
    */

    max_fd = -1;

    return ATUN_OK;
}

/*
static void
atun_select_done(atun_cycle_t *cycle)
{
    atun_free(event_index);

    event_index = NULL;
}
*/

atun_int_t
atun_select_add_event(atun_event_t *ev, atun_uint_t event, atun_uint_t flags)
{
    atun_connection_t  *c = static_cast<atun_connection_t *>(ev->data);

    //atun_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
    //               "select add event fd:%d ev:%i", c->fd, event);

    if (ev->index != ATUN_INVALID_INDEX) {
        //atun_log_error(NGX_LOG_ALERT, ev->log, 0,
        //              "select event fd:%d ev:%i is already set", c->fd, event);
        return ATUN_OK;
    }

    if ((event == ATUN_READ_EVENT && ev->write)
            || (event == ATUN_WRITE_EVENT && !ev->write)) {
        //atun_log_error(NGX_LOG_ALERT, ev->log, 0,
        //              "invalid select %s event fd:%d ev:%i",
        //              ev->write ? "write" : "read", c->fd, event);
        return ATUN_ERROR;
    }

    if (event == ATUN_READ_EVENT) {
        FD_SET(c->fd, &master_read_fd_set);
    } else if (event == ATUN_WRITE_EVENT) {
        std::cout << "add write fd " << c->fd << "\n";
        FD_SET(c->fd, &master_write_fd_set);
    }

    if (max_fd != -1 && max_fd < c->fd) {
        max_fd = c->fd;
    }

    std::cout << "add fd " << c->fd << "\n";

    event_index[nevents] = ev;
    ev->index = nevents;
    nevents++;

    return ATUN_OK;
}

atun_int_t
atun_select_del_event(atun_event_t *ev, atun_int_t event, atun_uint_t flags)
{
    atun_connection_t  *c = static_cast<atun_connection_t *>(ev->data);

    //ev->active = 0;

    if (ev->index == ATUN_INVALID_INDEX) {
        return ATUN_OK;
    }

    std::cout << "del fd 1 " << c->fd << "\n";

    //atun_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
    //               "select del event fd:%d ev:%i", c->fd, event);

    if (event == ATUN_READ_EVENT) {
        FD_CLR(c->fd, &master_read_fd_set);
    } else if (event == ATUN_WRITE_EVENT) {
        FD_CLR(c->fd, &master_write_fd_set);
    }

    if (max_fd == c->fd) {
        max_fd = -1;
    }

    if (ev->index < --nevents) {
        std::cout << "del fd 2 " << c->fd << "\n";
        atun_event_t *e = event_index[nevents];
        event_index[ev->index] = e;
        e->index = ev->index;
    }

    ev->index = ATUN_INVALID_INDEX;

    return ATUN_OK;
}

uint32_t
atun_select_process_events(atun_uint_t timer)
{
    int                ready, nready;
    atun_err_t          err;
    atun_uint_t         i, found;
    atun_event_t       *ev;
    //atun_queue_t       *queue;
    struct timeval     tv, *tp;
    atun_connection_t  *c;

    if (max_fd == -1) {
        for (i = 0; i < nevents; i++) {
            c = static_cast<atun_connection_t *>(event_index[i]->data);
            if (max_fd < c->fd) {
                max_fd = c->fd;
            }
        }

        //atun_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
        //               "change max_fd: %i", max_fd);
    }

    if (timer == ATUN_TIMER_INFINITE) {
        tp = NULL;

    } else {
        tv.tv_sec = (long)(timer / 1000);
        tv.tv_usec = (long)((timer % 1000) * 1000);
        tp = &tv;
    }

    //atun_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
    //               "select timer: %M", timer);

    work_read_fd_set = master_read_fd_set;
    work_write_fd_set = master_write_fd_set;

    //std::cout << "max fd " << max_fd << "\n";

    ready = select(max_fd + 1, &work_read_fd_set, &work_write_fd_set, NULL, tp);

    err = (ready == -1) ? atun_errno : 0;

    //if (flags & NGX_UPDATE_TIME || atun_event_timer_alarm) {
    //    atun_time_update();
    //}

    //atun_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
    //               "select ready %d", ready);

    if (err) {
        //atun_uint_t  level;

        if (err == EINTR) {

            //if (atun_event_timer_alarm) {
            //    atun_event_timer_alarm = 0;
            //    return NGX_OK;
            //}

            //level = NGX_LOG_INFO;

        } else {
            //level = NGX_LOG_ALERT;
        }

        //atun_log_error(level, cycle->log, err, "select() failed");

        if (err == EBADF) {
            atun_select_repair_fd_sets();
        }

        return ATUN_ERROR;
    }

    if (ready == 0) {
        //if (timer != NGX_TIMER_INFINITE) {
        //    return NGX_OK;
        //}

        //atun_log_error(NGX_LOG_ALERT, cycle->log, 0,
        //              "select() returned no events without timeout");
        //return NGX_ERROR;
    }

    nready = 0;

    for (i = 0; i < nevents; i++) {

        ev = event_index[i];
        c = static_cast<atun_connection_t *>(ev->data);
        found = 0;

        if (ev->write) {
            if (FD_ISSET(c->fd, &work_write_fd_set)) {
                
                //std::cout << "writable fd..." << c->fd << "\n";
                found = 1;
                //atun_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                //               "select write %d", c->fd);
            }

        } else {
            if (FD_ISSET(c->fd, &work_read_fd_set)) {
                found = 1;
                //atun_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                //               "select read %d", c->fd);
            }
        }

        if (found) {

            //ev->ready = 1;

            atun_post_event(ev);
            /*
            if (ev->accept) {

                atun_posted_accept_events.push(ev);
            } else {
                atun_posted_events.push(ev);
            }
            */

            //atun_post_event(ev, queue);

            nready++;
        }
    }

    if (ready != nready) {
        //atun_log_error(NGX_LOG_ALERT, cycle->log, 0,
        //              "select ready != events: %d:%d", ready, nready);

        atun_select_repair_fd_sets();
    }

    return ATUN_OK;
}


static void
atun_select_repair_fd_sets()
{
    int           n;
    socklen_t     len;
    atun_err_t     err;
    atun_socket_t  s;

    for (s = 0; s <= max_fd; s++) {

        if (FD_ISSET(s, &master_read_fd_set) == 0) {
            continue;
        }

        len = sizeof(int);

        if (getsockopt(s, SOL_SOCKET, SO_TYPE, &n, &len) == -1) {
            err = atun_socket_errno;

            //atun_log_error(NGX_LOG_ALERT, cycle->log, err,
            //              "invalid descriptor #%d in read fd_set", s);

            FD_CLR(s, &master_read_fd_set);
        }
    }

    for (s = 0; s <= max_fd; s++) {

        if (FD_ISSET(s, &master_write_fd_set) == 0) {
            continue;
        }

        len = sizeof(int);

        if (getsockopt(s, SOL_SOCKET, SO_TYPE, &n, &len) == -1) {

            err = atun_socket_errno;

            //atun_log_error(NGX_LOG_ALERT, cycle->log, err,
            //              "invalid descriptor #%d in write fd_set", s);

            FD_CLR(s, &master_write_fd_set);
        }
    }

    max_fd = -1;
}
