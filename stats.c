/* SPDX-License-Identifier: GPL-2.0-or-later */
/* SPDX-FileCopyrightText: 2024 - 1984 Hosting Company <1984@1984.is> */
/* SPDX-FileCopyrightText: 2024 - Freyx Solutions <frey@freyx.com> */
/* SPDX-FileContributor: Freysteinn Alfredsson <freysteinn@freysteinn.com> */
/* SPDX-FileContributor: Julius Thor Bess Rikardsson <juliusbess@gmail.com> */

#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <linux/neighbour.h>

#include "json_writer.h"
#include "neighsnoopd.h"

extern struct env env;
extern GHashTable *db_link_cache;
extern GHashTable *db_network_cache;
extern GHashTable *db_fdb_cache;
extern GHashTable *db_neigh_cache;

extern GHashTable *db_lookup_addr;
extern GHashTable *db_lookup_vlan_networkid;
extern GHashTable *db_lookup_addr_ifindex;

extern GTree *db_timer_cache;


void stats_send_link(gpointer key, gpointer value, gpointer user_data)
{
    json_writer_t *jw = (json_writer_t *)user_data;
    char time_str[128];
    GList *iter;

    struct link_cache *link = (struct link_cache *)value;
    char mac_str[MAC_ADDR_STR_LEN];
    mac_to_string((unsigned char *)mac_str, link->mac, MAC_ADDR_STR_LEN);

    jsonw_start_object(jw);

    jsonw_string_field(jw, "ifname", link->ifname);
    jsonw_uint_field(jw, "link_ifindex", link->link_ifindex);
    jsonw_string_field(jw, "mac", mac_str);
    jsonw_string_field(jw, "kind", link->kind);
    jsonw_string_field(jw, "slave_kind", link->slave_kind);
    jsonw_uint_field(jw, "vlan_protocol", link->vlan_protocol);
    jsonw_uint_field(jw, "vlan_id", link->vlan_id);
    jsonw_bool_field(jw, "has_vlan", link->has_vlan);
    jsonw_bool_field(jw, "is_svi", link->is_svi);
    jsonw_bool_field(jw, "is_macvlan", link->is_macvlan);

    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S",
             localtime(&link->times.created.tv_sec));
    jsonw_string_field(jw, "created", time_str);

    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S",
             localtime(&link->times.referenced.tv_sec));
    jsonw_string_field(jw, "referenced", time_str);

    jsonw_name(jw, "networks");
    jsonw_start_array(jw);

    // List network_list
    iter = link->network_list;
    while (iter != NULL) {
        struct link_network_cache *ln = (struct link_network_cache *)iter->data;

        jsonw_start_object(jw);

        jsonw_uint_field(jw, "id", ln->network->id);
        jsonw_string_field(jw, "network_str", ln->network->network_str);
        jsonw_uint_field(jw, "prefixlen", ln->network->prefixlen);

        jsonw_end_object(jw);

        iter = g_list_next(iter);
    }

    jsonw_end_array(jw);

    jsonw_end_object(jw);
}

void stats_send_links(json_writer_t *jw)
{
    jsonw_name(jw, "links");
    jsonw_start_array(jw);

    g_hash_table_foreach(db_link_cache, stats_send_link, jw);

    jsonw_end_array(jw);
}

void stats_send_network(gpointer key, gpointer value, gpointer user_data)
{
    json_writer_t *jw = (json_writer_t *)user_data;
    char time_str[128];
    GList *iter;

    struct network_cache *network = (struct network_cache *)value;

    jsonw_start_object(jw);

    jsonw_uint_field(jw, "id", network->id);
    jsonw_string_field(jw, "network", network->network_str);
    jsonw_uint_field(jw, "prefixlen", network->prefixlen);
    jsonw_uint_field(jw, "true_prefixlen", network->true_prefixlen);
    jsonw_uint_field(jw, "refcnt", network->refcnt);

    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S",
             localtime(&network->times.created.tv_sec));
    jsonw_string_field(jw, "created", time_str);

    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S",
             localtime(&network->times.referenced.tv_sec));
    jsonw_string_field(jw, "referenced", time_str);

    jsonw_name(jw, "links");
    jsonw_start_array(jw);

    // List link_list
    iter = network->links;
    while (iter != NULL) {
        char ip_str[INET6_ADDRSTRLEN];
        struct link_network_cache *ln = (struct link_network_cache *)
            iter->data;

        format_ip_address(ip_str, sizeof(ip_str), &ln->ip);

        jsonw_start_object(jw);

        jsonw_string_field(jw, "ifname", ln->link->ifname);
        jsonw_string_field(jw, "ip", ip_str);

        jsonw_end_object(jw);

        iter = g_list_next(iter);
    }

    jsonw_end_array(jw);

    jsonw_end_object(jw);
}

void stats_send_networks(json_writer_t *jw)
{
    jsonw_name(jw, "networks");
    jsonw_start_array(jw);

    g_hash_table_foreach(db_network_cache, stats_send_network, jw);

    jsonw_end_array(jw);
}

void stats_send_fdb(gpointer key, gpointer value, gpointer user_data)
{
    json_writer_t *jw = (json_writer_t *)user_data;
    char mac_str[MAC_ADDR_STR_LEN];
    char time_str[128];
    struct fdb_cache *fdb = (struct fdb_cache *)value;

    mac_to_string((unsigned char *)mac_str, fdb->mac, MAC_ADDR_STR_LEN);

    jsonw_start_object(jw);

    jsonw_string_field(jw, "mac", mac_str);
    jsonw_uint_field(jw, "ifindex", fdb->link->ifindex);
    jsonw_uint_field(jw, "vlan_id", fdb->vlan_id);

    jsonw_uint_field(jw, "reference_count", fdb->reference_count);

    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S",
             localtime(&fdb->times.created.tv_sec));
    jsonw_string_field(jw, "created", time_str);

    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S",
             localtime(&fdb->times.referenced.tv_sec));
    jsonw_string_field(jw, "referenced", time_str);

    jsonw_end_object(jw);
}

void stats_send_fdbs(json_writer_t *jw)
{
    jsonw_name(jw, "fdb");
    jsonw_start_array(jw);

    g_hash_table_foreach(db_fdb_cache, stats_send_fdb, jw);

    jsonw_end_array(jw);
}

void stats_send_neigh(gpointer key, gpointer value, gpointer user_data)
{
    json_writer_t *jw = (json_writer_t *)user_data;
    char time_str[128];
    struct neigh_cache *neigh = (struct neigh_cache *)value;
    char mac_str[MAC_ADDR_STR_LEN];

    mac_to_string((unsigned char *)mac_str, neigh->mac, MAC_ADDR_STR_LEN);

    jsonw_start_object(jw);

    jsonw_uint_field(jw, "id", neigh->id);
    jsonw_uint_field(jw, "ifindex", neigh->ifindex);
    jsonw_string_field(jw, "mac", mac_str);
    jsonw_string_field(jw, "ip", neigh->ip_str);
    switch (neigh->nud_state) {
    case NUD_INCOMPLETE:
        jsonw_string_field(jw, "nud_state", "incomplete");
        break;
    case NUD_REACHABLE:
        jsonw_string_field(jw, "nud_state", "reachable");
        break;
    case NUD_STALE:
        jsonw_string_field(jw, "nud_state", "stale");
        break;
    case NUD_DELAY:
        jsonw_string_field(jw, "nud_state", "delay");
        break;
    case NUD_PROBE:
        jsonw_string_field(jw, "nud_state", "probe");
        break;
    case NUD_FAILED:
        jsonw_string_field(jw, "nud_state", "failed");
        break;
    case NUD_NOARP:
        jsonw_string_field(jw, "nud_state", "noarp");
        break;
    case NUD_PERMANENT:
        jsonw_string_field(jw, "nud_state", "permanent");
        break;
    default:
        jsonw_string_field(jw, "nud_state", "unknown");
        break;
    }
    if (neigh->timer) {
        jsonw_uint_field(jw, "timer_id", neigh->timer->id);
        jsonw_uint_field(jw, "timer_expiry_sec",
                         neigh->timer->timer_events->expiry.tv_sec);
        jsonw_uint_field(jw, "timer_expiry_nsec",
                         neigh->timer->timer_events->expiry.tv_nsec);
    }

    jsonw_uint_field(jw, "update_count", neigh->update_count);
    jsonw_uint_field(jw, "reference_count", neigh->reference_count);

    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S",
             localtime(&neigh->times.created.tv_sec));
    jsonw_string_field(jw, "created", time_str);

    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S",
             localtime(&neigh->times.referenced.tv_sec));
    jsonw_string_field(jw, "referenced", time_str);

    jsonw_end_object(jw);
}

void stats_send_neighs(json_writer_t *jw)
{
    jsonw_name(jw, "neighs");
    jsonw_start_array(jw);

    g_hash_table_foreach(db_neigh_cache, stats_send_neigh, jw);

    jsonw_end_array(jw);
}

void stats_send_lookup_addr_entry(gpointer key, gpointer value, gpointer user_data)
{
    json_writer_t *jw = (json_writer_t *)user_data;
    struct in6_addr *addr = (struct in6_addr *)key;
    struct network_cache *network = (struct network_cache *)value;
    char ip_str[INET6_ADDRSTRLEN];

    format_ip_address(ip_str, sizeof(ip_str), addr);

    jsonw_start_object(jw);

    jsonw_name(jw, "key");
    jsonw_start_object(jw);
    jsonw_string_field(jw, "ip", ip_str);
    jsonw_end_object(jw);

    jsonw_uint_field(jw, "network_id", network->id);
    jsonw_string_field(jw, "network", network->network_str);

    jsonw_end_object(jw);
}

void stats_send_lookup_addr(json_writer_t *jw)
{
    jsonw_name(jw, "lookup_addr");
    jsonw_start_array(jw);

    g_hash_table_foreach(db_lookup_addr, stats_send_lookup_addr_entry, jw);

    jsonw_end_array(jw);
}

void stats_send_lookup_vlan_networkid_entry(gpointer key, gpointer value,
                                            gpointer user_data)
{
    json_writer_t *jw = (json_writer_t *)user_data;
    struct vlan_networkid_cache_key *key_entry =
        (struct vlan_networkid_cache_key *)key;
    struct link_network_cache *link_net = (struct link_network_cache *)value;
    char value_ip_str[INET6_ADDRSTRLEN];

    format_ip_address(value_ip_str, sizeof(value_ip_str), &link_net->ip);

    jsonw_start_object(jw);

    jsonw_name(jw, "key");
    jsonw_start_object(jw);
    jsonw_uint_field(jw, "vlan_id", key_entry->vlan_id);
    jsonw_uint_field(jw, "network_id", key_entry->network_id);
    jsonw_end_object(jw);

    jsonw_name(jw, "value");
    jsonw_start_object(jw);
    jsonw_string_field(jw, "ip", value_ip_str);
    jsonw_string_field(jw, "ifname", link_net->link->ifname);
    jsonw_uint_field(jw, "network_id", link_net->network->id);
    jsonw_end_object(jw);

    jsonw_end_object(jw);
}

void stats_send_lookup_vlan_networkid(json_writer_t *jw)
{
    jsonw_name(jw, "lookup_vlan_networkid");
    jsonw_start_array(jw);

    g_hash_table_foreach(db_lookup_vlan_networkid,
                         stats_send_lookup_vlan_networkid_entry, jw);

    jsonw_end_array(jw);
}

void stats_send_lookup_addr_ifindex_entry(gpointer key, gpointer value,
                                          gpointer user_data)
{
    json_writer_t *jw = (json_writer_t *)user_data;
    struct ifindex_addr_cache_key *key_entry = (struct ifindex_addr_cache_key *)key;
    struct link_network_cache *link_net = (struct link_network_cache *)value;
    char key_ip_str[INET6_ADDRSTRLEN];
    char value_ip_str[INET6_ADDRSTRLEN];

    format_ip_address(key_ip_str, sizeof(key_ip_str), &key_entry->network_ip);
    format_ip_address(value_ip_str, sizeof(value_ip_str), &link_net->ip);

    jsonw_start_object(jw);

    jsonw_name(jw, "key");
    jsonw_start_object(jw);
    jsonw_uint_field(jw, "ifindex", key_entry->ifindex);
    jsonw_string_field(jw, "network_ip", key_ip_str);
    jsonw_end_object(jw);

    jsonw_name(jw, "value");
    jsonw_start_object(jw);
    jsonw_string_field(jw, "ip", value_ip_str);
    jsonw_string_field(jw, "ifname", link_net->link->ifname);
    jsonw_uint_field(jw, "network_id", link_net->network->id);
    jsonw_end_object(jw);

    jsonw_end_object(jw);
}

void stats_send_lookup_addr_ifindex(json_writer_t *jw)
{
    jsonw_name(jw, "lookup_addr_ifindex");
    jsonw_start_array(jw);

    g_hash_table_foreach(db_lookup_addr_ifindex,
                         stats_send_lookup_addr_ifindex_entry, jw);

    jsonw_end_array(jw);
}

gboolean stats_send_timer(gpointer key, gpointer value, gpointer data)
{
    json_writer_t *jw = (json_writer_t *)data;
    struct timer_events *timer = (struct timer_events *)value;
    GList *iter;

    jsonw_start_object(jw);

    jsonw_uint_field(jw, "id", timer->id);
    jsonw_uint_field(jw, "expiry_sec", timer->expiry.tv_sec);
    jsonw_uint_field(jw, "expiry_nsec", timer->expiry.tv_nsec);

    jsonw_name(jw, "timer_cmds");
    jsonw_start_array(jw);

    iter = timer->timer_cmds;
    while (iter != NULL) {
        union timer_cmd *cmd = (union timer_cmd *)iter->data;

        jsonw_start_object(jw);

        jsonw_uint_field(jw, "id", cmd->neigh.id);
        switch (cmd->base.type) {
        case TIMER_NEIGH:
            jsonw_string_field(jw, "type", "neigh");
            jsonw_uint_field(jw, "neigh_id", cmd->neigh.neigh->id);
            break;
        default:
            jsonw_string_field(jw, "type", "unknown");
            break;
        }

        jsonw_end_object(jw);

        iter = g_list_next(iter);
    }

    jsonw_end_array(jw);

    jsonw_end_object(jw);

    return false;
}

void stats_send_timers(json_writer_t *jw)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);

    jsonw_name(jw, "current_time");
    jsonw_start_object(jw);
    jsonw_uint_field(jw, "sec", now.tv_sec);
    jsonw_uint_field(jw, "nsec", now.tv_nsec);
    jsonw_end_object(jw);

    jsonw_name(jw, "timers");
    jsonw_start_array(jw);

    g_tree_foreach(db_timer_cache, stats_send_timer, jw);

    jsonw_end_array(jw);
}

int handle_stats_server_request(void)
{
    int err = 0;
    int flags;
    int memfd_writer_fd;
    FILE *client;

    env.stats_client_fd = accept(env.stats_server_fd, NULL, NULL);
    if (env.stats_client_fd == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            goto out;
        pr_err(errno, "accept");
        err = errno;
        goto out;
    }

    // Set the client socket to non-blocking mode
    flags = fcntl(env.stats_client_fd, F_GETFL, 0);
    fcntl(env.stats_client_fd, F_SETFL, flags | O_NONBLOCK);

    // Create a memfd
    env.memfd_fd = memfd_create("json_stats", MFD_ALLOW_SEALING);
    if (env.memfd_fd == -1) {
        perror("memfd_create");
        err = -errno;
        goto out;
    }

    // Prepare the memfd for writing
    memfd_writer_fd = dup(env.memfd_fd);
    client = fdopen(memfd_writer_fd, "w");
    if (client == NULL) {
        pr_err(errno, "fdopen");
        err = -errno;
        goto out;
    }

    // Add JSON data to the memfd
    json_writer_t *wr = jsonw_new(client);
    jsonw_pretty(wr, true);

    jsonw_start_object(wr);

    stats_send_links(wr);
    stats_send_networks(wr);
    stats_send_fdbs(wr);
    stats_send_neighs(wr);
    stats_send_lookup_addr(wr);
    stats_send_lookup_vlan_networkid(wr);
    stats_send_lookup_addr_ifindex(wr);
    stats_send_timers(wr);

    jsonw_end_object(wr);
    jsonw_destroy(&wr);

    fclose(client);

out:
    return err;
}


int setup_stats(void)
{
    int err = 0;
    int flags;
    struct sockaddr_un addr;

    // memfd file descriptor
    env.number_of_fds++;

    env.stats_server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (env.stats_server_fd == -1) {
        perror("socket");
        err = -errno;
        goto out;
    }
    env.number_of_fds++; // Add one for the server socket
    env.number_of_fds++; // Add one for the client socket

    // Set up the socket address
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, STATS_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    // Remove any existing socket file and bind to the address
    unlink(STATS_SOCKET_PATH);
    if (bind(env.stats_server_fd, (struct sockaddr*)&addr,
             sizeof(struct sockaddr_un)) == -1) {
        perror("bind");
        err = -errno;
        goto out;
    }

    // Listen for incoming connections
    if (listen(env.stats_server_fd, 1) == -1) {
        perror("listen");
        err = -errno;
        goto out;
    }

    // Set the listening socket to non-blocking mode
    flags = fcntl(env.stats_server_fd, F_GETFL, 0);
    fcntl(env.stats_server_fd, F_SETFL, flags | O_NONBLOCK);

out:
    return err;
}

void cleanup_stats(void)
{
    close(env.stats_server_fd);
    unlink(STATS_SOCKET_PATH);
}
