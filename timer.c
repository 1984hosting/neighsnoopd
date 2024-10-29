/* SPDX-License-Identifier: GPL-2.0-or-later */
/* SPDX-FileCopyrightText: 2024 - 1984 Hosting Company <1984@1984.is> */
/* SPDX-FileCopyrightText: 2024 - Freyx Solutions <frey@freyx.com> */
/* SPDX-FileContributor: Freysteinn Alfredsson <freysteinn@freysteinn.com> */
/* SPDX-FileContributor: Julius Thor Bess Rikardsson <juliusbess@gmail.com> */

/**
 * @file timer.c
 * @brief Handles timer event handling
 *
 * Timeres within neighsnoopd are handled by a timerfd and pulled by epoll. The
 * events are kept within a struct timer_events that keeps track of all timer
 * commands that trigger simultaneously. The primary data structure is the
 * GTree *db_timer_cache, a tree of struct timer_events sorted by the next
 * struct timer_events that will trigger.
 *
 * @see neighsnoopd.h for the main header data structures and functions.
 */

#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/timerfd.h>

// Include epoll
#include <sys/epoll.h>

#include "neighsnoopd.h"

static void timer_add_seconds_to_timespec(struct timespec *ts, double seconds);
static union timer_cmd *timer_new(enum timer_type type);
static int timer_process_events(void);
static gint timer_compare_expiry(gconstpointer left, gconstpointer right,
                                 gpointer user_data);
static int timer_add_event(union timer_cmd *cmd, struct timespec expiry);
static struct timer_events *timer_get_next_timer_events(void);
static int timer_update_timerfd(void);

extern struct env env;

GTree *db_timer_cache;

int handle_timer_events(void)
{
    uint64_t expirations;
    ssize_t s;

    s = read(env.timerfd_fd, &expirations, sizeof(expirations));
    if (s != sizeof(expirations)) {
        pr_err(errno, "Failed to read timerfd");
        return -errno;
    }

    timer_process_events();
    timer_update_timerfd();

    return 0;
}

static void timer_add_seconds_to_timespec(struct timespec *ts, double seconds)
{
    // Convert all to nanoseconds
    int64_t total_nanoseconds = (int64_t)(seconds * 1e9);

    ts->tv_sec += total_nanoseconds / (int64_t)1e9;
    ts->tv_nsec += total_nanoseconds % (int64_t)1e9;

    // Normalize tv_nsec if needed
    if (ts->tv_nsec >= 1e9) {
        ts->tv_sec += ts->tv_nsec / (int64_t)1e9;
        ts->tv_nsec %= (int64_t)1e9;
    } else if (ts->tv_nsec < 0) {
        ts->tv_sec -= 1 + (-ts->tv_nsec / (int64_t)1e9);
        ts->tv_nsec = 1e9 + ts->tv_nsec % (int64_t)1e9;
    }
}

int timer_add_neigh(struct neigh_cache *neigh, double seconds)
{
    int ret = -1;
    struct timespec expiry;
    union timer_cmd *cmd = timer_new(TIMER_NEIGH);

    if (!cmd)
        goto out;

    ret = clock_gettime(CLOCK_MONOTONIC, &expiry);
    if (ret) {
        pr_err(errno, "Failed to get current time");
        ret = -errno;
        goto out;
    }

    timer_add_seconds_to_timespec(&expiry, seconds);

    cmd->neigh.neigh = neigh;
    neigh->timer = &cmd->neigh;

    ret = timer_add_event(cmd, expiry);

out:
    return ret;
}

static union timer_cmd *timer_new(enum timer_type type)
{
    static __u64 cmd_id = 1;
    union timer_cmd *cmd = NULL;

    if (type == TIMER_NONE)
        goto out;

    cmd = g_new0(union timer_cmd, 1);
    if (!cmd)
        goto out;

    cmd->neigh.type = type;
    cmd->neigh.id = cmd_id++;

out:
    return cmd;
}

static void timer_del(union timer_cmd *cmd)
{
    cmd->base.timer_events = NULL;

    switch (cmd->base.type) {
    case TIMER_NEIGH:
        cmd->neigh.neigh->timer = NULL;
        break;
    default:
        break;
    }

    g_free(cmd);
}

static int timer_process_events(void)
{
    int ret = 0;
    struct timer_events *timer_events;
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now)) {
        pr_err(errno, "Failed to get current time");
        ret = -errno;
        goto out;
    }

    while ((timer_events = timer_get_next_timer_events())) {
        GList *iter;

        if (now.tv_sec < timer_events->expiry.tv_sec ||
            (now.tv_sec == timer_events->expiry.tv_sec &&
             now.tv_nsec < timer_events->expiry.tv_nsec)) {
            break;
        }

        iter = timer_events->timer_cmds;
        while (iter) {
            union timer_cmd *cmd = timer_events->timer_cmds->data;

            handle_timer_event(cmd);

            timer_del(cmd);

            iter = g_list_next(iter);
        }
        g_list_free(timer_events->timer_cmds);

        g_tree_remove(db_timer_cache, &timer_events->expiry);
        g_free(timer_events);
    }

    ret = timer_update_timerfd();

out:
    return ret;
}

// Comparator for GTree: compares timespec structs
static gint timer_compare_expiry(gconstpointer left, gconstpointer right,
                                 gpointer user_data)
{
    const struct timer_events *key_left = left;
    const struct timer_events *key_right = right;
    if (key_left->expiry.tv_sec == key_right->expiry.tv_sec)
        return key_left->expiry.tv_nsec - key_right->expiry.tv_nsec;
    return key_left->expiry.tv_sec - key_right->expiry.tv_sec;
}

// Add a timer event to the GTree
static int timer_add_event(union timer_cmd *cmd, struct timespec expiry)
{
    int ret;
    GList *new_list;
    static __u64 timer_events_id = 1;
    struct timer_events *timer_events = g_tree_lookup(db_timer_cache, &expiry);
    if (timer_events) {
        new_list = g_list_append(timer_events->timer_cmds, cmd);
        if (!new_list) {
            pr_err(errno, "Failed to append timer event");
            ret = -errno;
            goto out;
        }
        timer_events->timer_cmds = new_list;
        cmd->base.timer_events = timer_events;
    } else {
        timer_events = g_new0(struct timer_events, 1);
        if (!timer_events) {
            pr_err(errno, "Failed to allocate timer_events");
            ret = -errno;
            goto out;
        }

        timer_events->id = timer_events_id++;
        timer_events->expiry = expiry;
        new_list = g_list_append(timer_events->timer_cmds, cmd);
        if (!new_list) {
            pr_err(errno, "Failed to append timer event");
            ret = -errno;
            goto out;
        }
        timer_events->timer_cmds = new_list;
        cmd->base.timer_events = timer_events;
        g_tree_insert(db_timer_cache, &timer_events->expiry, timer_events);
    }

    ret = timer_update_timerfd();

out:
    return ret;
}

// Retrieve and remove the soonest timer event(s)
static struct timer_events *timer_get_next_timer_events(void)
{
    GTreeNode *node;
    if (g_tree_nnodes(db_timer_cache) == 0)
        return NULL;

    node = g_tree_node_first(db_timer_cache);

    return g_tree_node_value(node);
}

// Remove a specific timer event by ID (searches each list)
int timer_remove_event(union timer_cmd *cmd)
{
    struct timer_events *timer_events;
    GList *iter;

    timer_events = g_tree_lookup(db_timer_cache,
                                 &cmd->base.timer_events->expiry);

    // Check length of timer events in cmd
    if (timer_events == NULL)
        return -1;

    // Iterate through the list of timer events
    iter = timer_events->timer_cmds;
    while (iter) {
        if (iter->data == cmd) {
            timer_events->timer_cmds = g_list_delete_link(
                timer_events->timer_cmds, iter);
            timer_del(cmd);
            break;
        }
        iter = g_list_next(iter);
    }

    if (g_list_length(timer_events->timer_cmds) == 0) {
        g_tree_remove(db_timer_cache, &timer_events->expiry);
        g_free(timer_events);
    }

    return 0;
}

// Update epoll timer using the next timer event
static int timer_update_timerfd(void)
{
    int ret = 0;
    struct timespec now;
    struct timer_events *timer_events = timer_get_next_timer_events();
    struct itimerspec next_expiry = {0}; // Default is to stop the timer

    if (!timer_events)
        goto out;

    ret = clock_gettime(CLOCK_MONOTONIC, &now);
    if (ret) {
        pr_err(errno, "Failed to get current time");
        ret = -errno;
        goto out;
    }

    next_expiry.it_value.tv_sec = timer_events->expiry.tv_sec - now.tv_sec;
    next_expiry.it_value.tv_nsec = timer_events->expiry.tv_nsec - now.tv_nsec;
    if (next_expiry.it_value.tv_nsec < 0) {
        next_expiry.it_value.tv_sec -= 1;
        next_expiry.it_value.tv_nsec += 1000000000;
    }

    timerfd_settime(env.timerfd_fd, 0, &next_expiry, NULL);
out:
    return ret;
}

int setup_timerfd(void)
{
    env.timerfd_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (env.timerfd_fd < 0) {
        perror("timerfd_create");
        return -1;
    }
    env.number_of_fds++;

    db_timer_cache = g_tree_new_full(timer_compare_expiry, NULL, NULL, NULL);

    return 0;
}

void cleanup_timerfd(void)
{
    close(env.timerfd_fd);
    g_tree_destroy(db_timer_cache);
}
