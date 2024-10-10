/* SPDX-License-Identifier: GPL-2.0-or-later */
/* SPDX-FileCopyrightText: 2024 - 1984 Hosting Company <1984@1984.is> */
/* SPDX-FileCopyrightText: 2024 - Freyx Solutions <frey@freyx.com> */
/* SPDX-FileContributor: Freysteinn Alfredsson <freysteinn@freysteinn.com> */
/* SPDX-FileContributor: Julius Thor Bess Rikardsson <juliusbess@gmail.com> */

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <time.h>
#include <linux/neighbour.h>

#include "neighsnoopd.h"

extern struct env env;

GHashTable *db_lookup_addr; // Lookup network by network IP
GHashTable *db_lookup_vlan_networkid; // Lookup link_network by
                                      // network_id and vlan_id

GHashTable *db_lookup_addr_ifindex; // Lookup network by network IP and ifindex

GHashTable *db_link_cache;
GHashTable *db_network_cache;
GHashTable *db_fdb_cache;
GHashTable *db_neigh_cache;

static guint vlan_networkid_cache_key_hash(gconstpointer key)
{
    const struct vlan_networkid_cache_key *k = key;
    guint hash = 0;

    // Hash the Network ID
    hash = hash * 31 + g_int_hash(&k->network_id);

    // Hash the VLAN ID
    hash = hash * 31 + g_int_hash(&k->vlan_id);

    return hash;
}

static gboolean vlan_networkid_cache_key_equal(gconstpointer left,
                                               gconstpointer right)
{
    const struct vlan_networkid_cache_key *key_left = left;
    const struct vlan_networkid_cache_key *key_right = right;

    // Compare Network ID
    if (key_left->network_id != key_right->network_id)
        return false;

    // Compare VLAN IDs
    if (key_left->vlan_id != key_right->vlan_id)
        return false;

    return true;
}

static guint addr_cache_key_hash(gconstpointer key)
{
    const struct in6_addr *k = key;
    guint hash = 0;

    // Hash the IP address
    for (guint i = 0; i < sizeof(*k); i++)
        hash = hash * 31 + k->s6_addr[i];

    return hash;
}

static gboolean addr_cache_key_equal(gconstpointer left,
                                          gconstpointer right)
{
    const struct in6_addr *key_left = left;
    const struct in6_addr *key_right = right;

    // Compare IP addresses
    if (memcmp(key_left, key_right,
               sizeof(*key_left)) != 0)
        return false;

    return true;
}

static guint ifindex_addr_key_hash(gconstpointer key)
{
    const struct ifindex_addr_cache_key *k = key;
    guint hash = 0;

    // Hash the IP address
    for (guint i = 0; i < sizeof(k->network_ip); i++)
        hash = hash * 31 + k->network_ip.s6_addr[i];

    // Hash the ifindex
    hash = hash * 31 + g_int_hash(&k->ifindex);

    return hash;
}

static gboolean ifindex_addr_key_equal(gconstpointer left,
                                       gconstpointer right)
{
    const struct ifindex_addr_cache_key *key_left = left;
    const struct ifindex_addr_cache_key *key_right = right;

    // Compare IP addresses
    if (memcmp(&key_left->network_ip, &key_right->network_ip,
               sizeof(key_left->network_ip)) != 0)
        return false;

    // Compare ifindex
    if (key_left->ifindex != key_right->ifindex)
        return false;

    return true;
}

struct link_cache *cache_add_link(struct netlink_link_cmd *link_cmd)
{
    struct link_cache *cache = NULL;

    cache = g_new0(struct link_cache, 1);
    if (!cache) {
        pr_err(errno, "g_new0");
        goto out;
    }

    cache->ifindex = link_cmd->ifindex;
    memcpy(cache->mac, link_cmd->mac, ETH_ALEN);
    snprintf(cache->ifname, sizeof(cache->ifname), "%s", link_cmd->ifname);
    snprintf(cache->kind, sizeof(cache->kind), "%s", link_cmd->kind);
    snprintf(cache->slave_kind, sizeof(cache->slave_kind), "%s",
             link_cmd->slave_kind);
    cache->vlan_id = link_cmd->vlan_id;
    cache->vlan_protocol = link_cmd->vlan_protocol;
    cache->has_vlan = link_cmd->has_vlan;
    cache->is_macvlan = link_cmd->is_macvlan;

    cache->network_list = NULL;
    cache->fdb_list = NULL;

    if (clock_gettime(CLOCK_REALTIME, &cache->times.created) == -1) {
        pr_err(errno, "clock_gettime");
        g_free(cache);
        goto out;
    }
    cache->times.referenced = cache->times.created;
    cache->times.updated = cache->times.created;

    g_hash_table_insert(db_link_cache, &cache->ifindex, cache);

out:
    return cache;
}

int cache_update_link(struct link_cache *cache,
                             struct netlink_link_cmd *link_cmd)
{
    bool updated = false;

    // TODO: Handle IP and subnet changes

    if (cache->link_ifindex != link_cmd->link_ifindex) {
        pr_debug("Updated link_ifindex for NIC: %s from %d to %d\n",
                 cache->ifname, cache->link_ifindex, link_cmd->link_ifindex);
        cache->link_ifindex = link_cmd->link_ifindex;
        updated = true;
    }

    if (strcmp(cache->ifname, link_cmd->ifname) != 0) {
        pr_debug("Updated ifname for NIC: %s from %s to %s\n",
                 cache->ifname, cache->ifname, link_cmd->ifname);
        strncpy(cache->ifname, link_cmd->ifname, sizeof(cache->ifname));
        updated = true;
    }

    if (memcmp(cache->mac, link_cmd->mac, ETH_ALEN) != 0) {
        pr_debug("Updated MAC address for NIC: %s\n", cache->ifname);
        memcpy(cache->mac, link_cmd->mac, ETH_ALEN);
        updated = true;
    }

    if (strcmp(cache->kind, link_cmd->kind) != 0) {
        pr_debug("Updated kind for NIC: %s from %s to %s\n",
                 cache->ifname, cache->kind, link_cmd->kind);
        strncpy(cache->kind, link_cmd->kind, sizeof(cache->kind));
        updated = true;
    }

    if (strcmp(cache->slave_kind, link_cmd->slave_kind) != 0) {
        pr_debug("Updated slave_kind for NIC: %s from %s to %s\n",
                 cache->ifname, cache->slave_kind, link_cmd->slave_kind);
        strncpy(cache->slave_kind, link_cmd->slave_kind, sizeof(cache->slave_kind));
        updated = true;
    }

    if (cache->vlan_protocol != link_cmd->vlan_protocol) {
        pr_debug("Updated vlan_protocol for NIC: %s from %d to %d\n",
                 cache->ifname, cache->vlan_protocol, link_cmd->vlan_protocol);
        cache->vlan_protocol = link_cmd->vlan_protocol;
        updated = true;
    }

    if (cache->vlan_id != link_cmd->vlan_id) {
        pr_debug("Updated vlan_id for NIC: %s from %d to %d\n",
                 cache->ifname, cache->vlan_id, link_cmd->vlan_id);
        cache->vlan_id = link_cmd->vlan_id;
        updated = true;
    }

    if (cache->has_vlan != link_cmd->has_vlan) {
        pr_debug("Updated has_vlan for NIC: %s from %d to %d\n",
                 cache->ifname, cache->has_vlan, link_cmd->has_vlan);
        cache->has_vlan = link_cmd->has_vlan;
        updated = true;
    }

    if (cache->is_macvlan != link_cmd->is_macvlan) {
        pr_debug("Updated is_macvlan for NIC: %s from %d to %d\n",
                 cache->ifname, cache->is_macvlan, link_cmd->is_macvlan);
        cache->is_macvlan = link_cmd->is_macvlan;
        updated = true;
    }

    if (updated) {
        if (clock_gettime(CLOCK_REALTIME, &cache->times.updated) == -1) {
            pr_err(errno, "clock_gettime");
            return errno;
        }
    }
    return 0;
}

int cache_add_link_network(struct link_network_cache *link_network)
{
    int ret = 0;
    struct vlan_networkid_cache_key *vnid_key;
    struct ifindex_addr_cache_key *ifad_key;
    struct network_cache *network = link_network->network;
    struct link_cache *link = link_network->link;

    // Handle the VLAN/Network ID lookup cache
    vnid_key = g_new0(struct vlan_networkid_cache_key, 1);
    if (!vnid_key) {
        pr_err(errno, "g_new0");
        ret = -errno;
        goto out;
    }
    vnid_key->network_id = network->id,
    vnid_key->vlan_id = link->vlan_id,

    ifad_key = g_new0(struct ifindex_addr_cache_key, 1);
    if (!ifad_key) {
        g_free(vnid_key);
        pr_err(errno, "g_new0");
        ret = -errno;
        goto out;
    }
    ifad_key->network_ip = network->network;
    ifad_key->ifindex = link->ifindex;

    g_hash_table_insert(db_lookup_vlan_networkid, vnid_key, link_network);
    g_hash_table_insert(db_lookup_addr_ifindex, ifad_key, link_network);

    // Network reference
    network->links = g_list_append(network->links, link_network);
    network->refcnt++;

    // Link reference
    link->network_list = g_list_append(link->network_list, link_network);

out:
    return ret;
}

static void cache_del_link_network(struct link_network_cache *link_network)
{
    struct network_cache *network = link_network->network;
    struct link_cache *link = link_network->link;

    // Handle the VLAN/Network cache
    struct vlan_networkid_cache_key key = {
        .network_id = network->id,
        .vlan_id = link->vlan_id,
    };
    g_hash_table_remove(db_lookup_vlan_networkid, &key);

    struct ifindex_addr_cache_key addr_key = {
        .network_ip = network->network,
        .ifindex = link->ifindex,
    };
    g_hash_table_remove(db_lookup_addr_ifindex, &addr_key);

    // Network reference
    for (GList *iter = network->links; iter; iter = g_list_next(iter)) {
        struct link_network_cache *link_network_cache = iter->data;
        if (link_network_cache == link_network) {
            network->links = g_list_delete_link(network->links, iter);
            break;
        }
    }

    // Handle Link reference
    for (GList *iter = link->network_list; iter; iter = g_list_next(iter)) {
        struct network_cache *network_cache = iter->data;
        if (network_cache == network) {
            link->network_list = g_list_delete_link(link->network_list, iter);
            break;
        }
    }

    // Free the link network cache
    g_free(link_network);

    network->refcnt--;
}

struct link_cache *cache_get_link(__u32 ifindex)
{
    struct link_cache *cache;

    cache = g_hash_table_lookup(db_link_cache, &ifindex);
    if (!cache)
        goto out;


    if (clock_gettime(CLOCK_REALTIME, &cache->times.referenced) == -1) {
        pr_err(errno, "clock_gettime");
        cache = NULL;
        goto out;
    }
    cache->reference_count++;

out:
    return cache;
}

int cache_del_link(struct netlink_link_cmd *link_cmd)
{
    int ret = 0;
    GList *iter;
    struct link_cache *cache = g_hash_table_lookup(db_link_cache,
                                                   &link_cmd->ifindex);
    if (!cache) {
        ret = -1;
        goto out;
    }

    for (iter = cache->network_list; iter; iter = g_list_next(iter))
        cache_del_link_network(iter->data);

    for (iter = cache->fdb_list; iter; iter = g_list_next(iter)) {
        struct fdb_cache *fdb = iter->data;
        struct fdb_cache_key key = {
            .ifindex = fdb->link->ifindex,
            .vlan_id = fdb->vlan_id,
        };
        g_hash_table_remove(db_fdb_cache, &key);
    }

    g_hash_table_remove(db_link_cache, &link_cmd->ifindex);
    g_free(cache);

out:
    return ret;
}

struct link_network_cache *cache_new_link_network(void)
{
    return g_new0(struct link_network_cache, 1);
}

struct link_network_cache *cache_get_link_network_by_reply(
    struct neighbor_reply *neighbor_reply)
{
    struct link_network_cache *cache;
    struct vlan_networkid_cache_key key = {
        .network_id = neighbor_reply->network_id,
        .vlan_id = neighbor_reply->vlan_id,
    };

    cache = g_hash_table_lookup(db_lookup_vlan_networkid, &key);

    return cache;
}

struct link_network_cache *cache_get_link_network_by_addr(
    struct link_cache *link, struct in6_addr *ip)
{
    struct link_network_cache *cache;
    struct in6_addr network_addr;

    char ip_str[INET6_ADDRSTRLEN];
    format_ip_address(ip_str, sizeof(ip_str), ip);

    for (GList *iter = link->network_list; iter; iter = g_list_next(iter)) {
        cache = iter->data;

        network_addr = calculate_network_using_cidr(ip, cache->network->prefixlen);

        if (compare_ipv6_addresses(&network_addr, &cache->network->network))
            return cache;
    }

    return NULL;
}

struct link_network_cache *cache_get_link_network(int ifindex,
                                                  struct in6_addr network_ip)
{
    struct ifindex_addr_cache_key key = {
        .network_ip = network_ip,
        .ifindex = ifindex,
    };

    return g_hash_table_lookup(db_lookup_addr_ifindex, &key);
}

struct network_cache *cache_add_network(struct netlink_addr_cmd *addr_cmd)
{
    struct network_cache *cache = NULL;
    struct link_cache *link_cache;
    struct link_network_cache *link_network_cache;
    struct in6_addr *addr_key;
    struct network_entry key;
    struct network_value value = {0};

    static __u32 id = 1;

    link_cache = cache_get_link(addr_cmd->ifindex);
    if (!link_cache) {
        pr_err(0, "Link cache: Lookup: NIC: %d > Not found\n",
               addr_cmd->ifindex);
        goto err0;
    }

    cache = g_new0(struct network_cache, 1);
    if (!cache) {
        pr_err(errno, "g_new0");
        goto err0;
    }

    link_network_cache = g_new0(struct link_network_cache, 1);
    if (!link_network_cache) {
        pr_err(errno, "g_new0");
        goto err1;
    }

    cache->id = id++;
    cache->network = addr_cmd->network;
    cache->prefixlen = addr_cmd->prefixlen;
    cache->true_prefixlen = addr_cmd->true_prefixlen;
    format_ip_address(cache->network_str, sizeof(cache->network_str),
                      &cache->network);

    // Add to the network cache
    g_hash_table_insert(db_network_cache, &cache->id, cache);

    // Add to the network address lookup cache
    addr_key = g_new0(struct in6_addr, 1);
    if (!addr_key) {
        pr_err(errno, "g_new0");
        goto err2;
    }
    *addr_key = cache->network;
    g_hash_table_insert(db_lookup_addr, addr_key, cache);

    // Add link_network
    link_network_cache->ip = addr_cmd->ip;
    link_network_cache->network = cache;
    link_network_cache->link = link_cache;
    cache_add_link_network(link_network_cache);

    // Add the network to the eBPF
    key.prefixlen = cache->prefixlen;
    memcpy(&key.network, &cache->network, sizeof(cache->network));

    value.network_id = cache->id;

    if (bpf_map_update_elem(env.target_networks_fd, &key, &value,
                            BPF_ANY) < 0) {
        pr_err(errno, "bpf_map_update_elem");
        goto err3;
    }

    if (clock_gettime(CLOCK_REALTIME, &cache->times.created) == -1) {
        pr_err(errno, "clock_gettime");
        goto err3;
    }
    cache->times.referenced = cache->times.created;

    return cache;
err3:
    g_hash_table_remove(db_lookup_addr, addr_key);
    g_free(addr_key);
err2:
    g_hash_table_remove(db_network_cache, &cache->id);
err1:
    g_free(cache);
err0:
    return NULL;
}

struct network_cache *cache_get_network_by_id(__u32 network_id)
{
    struct network_cache *cache = NULL;

    cache = g_hash_table_lookup(db_network_cache, &network_id);
    if (!cache)
        goto out;

    if (clock_gettime(CLOCK_REALTIME, &cache->times.referenced) == -1) {
        pr_err(errno, "clock_gettime");
        goto out;
    }
    cache->reference_count++;

out:
    return cache;
}

struct network_cache *cache_get_network(struct netlink_addr_cmd *addr_cmd)
{
    return g_hash_table_lookup(db_lookup_addr, &addr_cmd->network);
}

int cache_del_network(struct netlink_addr_cmd *addr_cmd)
{
    int ret = 0;
    struct link_cache *link_cache;
    GList *iter;
    struct network_cache *network;
    struct link_network_cache *link_network;
    struct ifindex_addr_cache_key addr_key;
    struct network_entry key = {0};
    bool found = false;

    link_cache = cache_get_link(addr_cmd->ifindex);
    if (!link_cache)
        goto out;

    // Find network from the CIDR network address
    for (iter = link_cache->network_list; iter; iter = g_list_next(iter)) {
        link_network = iter->data;
        network = link_network->network;
        if (compare_ipv6_addresses(&network->network, &addr_cmd->ip) &&
            network->prefixlen == addr_cmd->prefixlen) {
            found = true;
            break;
        }
    }

    if (!found)
        goto out;

    // Remove network id lookup cache
    g_hash_table_remove(db_network_cache, &network->id);

    // Remove the network address lookup cache
    addr_key.network_ip = network->network;
    g_hash_table_remove(db_lookup_addr, &addr_key);

    // Remove all link/network links
    for (iter = network->links; iter; iter = g_list_next(iter))
        cache_del_link_network(iter->data);

    // Remove the network from the eBPF
    key.prefixlen = addr_cmd->prefixlen;
    memcpy(&key.network, &addr_cmd->ip, sizeof(addr_cmd->ip));

    if (bpf_map_delete_elem(env.target_networks_fd, &key) < 0) {
        pr_err(errno, "bpf_map_delete_elem");
        ret = errno;
    }

out:
    return ret;
}

static guint fdb_cache_key_hash(gconstpointer key) {
    const struct fdb_cache_key *k = key;
    guint hash = 0;

    // Hash the MAC address (treat as binary data)
    for (guint i = 0; i < ETH_ALEN; i++)
        hash = hash * 31 + k->mac[i];

    // Hash the ifindex
    hash = hash * 31 + g_int_hash(&k->ifindex);

    // Hash the VLAN ID
    hash = hash * 31 + g_int_hash(&k->vlan_id);

    return hash;
}

static gboolean fdb_cache_key_equal(gconstpointer left, gconstpointer right) {
    const struct fdb_cache_key *key_left = left;
    const struct fdb_cache_key *key_right = right;

    // Compare MAC addresses
    if (memcmp(key_left->mac, key_right->mac, ETH_ALEN) != 0)
        return false;

    // Compare ifindex
    if (key_left->ifindex != key_right->ifindex)
        return false;

    // Compare VLAN IDs
    if (key_left->vlan_id != key_right->vlan_id)
        return false;

    return true;
}

struct fdb_cache *cache_get_fdb(struct netlink_neigh_cmd *neigh_cmd)
{
    struct fdb_cache *cache = NULL;
    struct fdb_cache_key key = {
        .ifindex = neigh_cmd->ifindex,
        .vlan_id = neigh_cmd->vlan_id,
    };
    memcpy(key.mac, neigh_cmd->mac, ETH_ALEN);

    cache = g_hash_table_lookup(db_fdb_cache, &key);
    if (!cache)
        goto out;

    if (clock_gettime(CLOCK_REALTIME, &cache->times.referenced) == -1) {
        pr_err(errno, "clock_gettime");
        goto out;
    }
    cache->reference_count++;

out:
    return cache;
}

struct fdb_cache *cache_get_fdb_by_reply(struct neighbor_reply *neighbor_reply,
                                         int ifindex)
{
    struct netlink_neigh_cmd neigh = {
        .vlan_id = neighbor_reply->vlan_id,
        .ifindex = ifindex,
    };

    memcpy(neigh.mac, neighbor_reply->mac, ETH_ALEN);

    return cache_get_fdb(&neigh);
}

struct fdb_cache *cache_add_fdb(struct netlink_neigh_cmd *neigh_cmd)
{
    struct link_cache *link;
    struct fdb_cache *cache = NULL;
    struct fdb_cache_key *key;

    key = g_new0(struct fdb_cache_key, 1);
    if (!key) {
        pr_err(errno, "g_new0");
        goto err0;
    }
    memcpy(key->mac, neigh_cmd->mac, ETH_ALEN);
    key->ifindex = neigh_cmd->ifindex;
    key->vlan_id = neigh_cmd->vlan_id;

    link = cache_get_link(neigh_cmd->ifindex);
    if (!link) {
        pr_err(0, "FDB cache: Lookup: NIC: %d > Not found\n",
               neigh_cmd->ifindex);
        goto err1;
    }

    cache = g_new0(struct fdb_cache, 1);
    if (!cache) {
        pr_err(errno, "g_new0");
        goto err1;
    }

    memcpy(cache->mac, neigh_cmd->mac, ETH_ALEN);
    cache->link = link;
    cache->vlan_id = neigh_cmd->vlan_id;

    mac_to_string(cache->mac_str, cache->mac, sizeof(cache->mac_str));

    if (clock_gettime(CLOCK_REALTIME, &cache->times.created) == -1) {
        pr_err(errno, "clock_gettime");
        goto err2;
    }
    cache->times.referenced = cache->times.created;

    g_hash_table_insert(db_fdb_cache, key, cache);

    return cache;
err2:
    g_free(cache);
err1:
    g_free(key);
err0:
    return NULL;
}

int cache_del_fdb(struct netlink_neigh_cmd *neigh_cmd)
{
    int ret = -1;
    struct fdb_cache *cache;
    struct fdb_cache_key key;

    memcpy(key.mac, neigh_cmd->mac, ETH_ALEN);
    key.ifindex = neigh_cmd->ifindex;
    key.vlan_id = neigh_cmd->vlan_id;

    cache = g_hash_table_lookup(db_fdb_cache, &key);
    if (!cache)
        goto out;

    g_hash_table_remove(db_fdb_cache, &key);
    ret = 0;
out:
    return ret;
}

static guint neigh_cache_key_hash(gconstpointer key)
{
    const struct neigh_cache_key *k = key;
    guint hash = 0;

    // Hash the ifindex
    hash = hash * 31 + g_int_hash(&k->ifindex);

    // Hash the IP address
    for (guint i = 0; i < sizeof(k->ip); i++)
        hash = hash * 31 + k->ip.s6_addr[i];

    return hash;
}

static gboolean neigh_cache_key_equal(gconstpointer left, gconstpointer right)
{
    const struct neigh_cache_key *key_left = left;
    const struct neigh_cache_key *key_right = right;

    // Compare ifindex
    if (key_left->ifindex != key_right->ifindex)
        return false;

    // Compare IP addresses
    if (memcmp(&key_left->ip, &key_right->ip, sizeof(key_left->ip)) != 0)
        return false;

    return true;
}

struct neigh_cache *cache_add_neigh(struct link_network_cache *link_network,
                                    struct netlink_neigh_cmd *neigh_cmd)
{
    struct neigh_cache *cache;
    struct neigh_cache_key *key;

    key = g_new0(struct neigh_cache_key, 1);
    if (!key) {
        pr_err(errno, "g_new0");
        goto err0;
    }

    key->ifindex = neigh_cmd->ifindex;
    memcpy(&key->ip, &neigh_cmd->ip, sizeof(key->ip));

    cache = g_new0(struct neigh_cache, 1);
    if (!cache) {
        pr_err(errno, "g_new0");
        goto err1;
    }

    memcpy(cache->mac, neigh_cmd->mac, ETH_ALEN);
    memcpy(&cache->ip, &neigh_cmd->ip, sizeof(cache->ip));
    mac_to_string(cache->mac_str, cache->mac, sizeof(cache->mac_str));
    format_ip_address(cache->ip_str, sizeof(cache->ip_str), &cache->ip);
    cache->nud_state = neigh_cmd->nud_state;

    cache->sending_link_network = link_network;

    if (clock_gettime(CLOCK_REALTIME, &cache->times.created) == -1) {
        pr_err(errno, "clock_gettime");
        goto err2;
    }
    cache->times.referenced = cache->times.created;

    g_hash_table_insert(db_neigh_cache, key, cache);

    return cache;
err2:
    g_free(cache);
err1:
    g_free(key);
err0:
    return NULL;
}

struct neigh_cache *cache_get_neigh(struct netlink_neigh_cmd *neigh_cmd)
{
    struct neigh_cache *cache = NULL;
    struct neigh_cache_key key;

    key.ifindex = neigh_cmd->ifindex;
    memcpy(&key.ip, &neigh_cmd->ip, sizeof(key.ip));

    cache = g_hash_table_lookup(db_neigh_cache, &key);
    if (!cache)
        goto out;

    if (clock_gettime(CLOCK_REALTIME, &cache->times.referenced) == -1) {
        pr_err(errno, "clock_gettime");
        goto out;
    }
    cache->reference_count++;

out:
    return cache;
}

struct neigh_cache *cache_get_neigh_by_reply(
    struct neighbor_reply *neighbor_reply, int ifindex)
{
    struct netlink_neigh_cmd neigh = {
        .ifindex = ifindex,
    };
    memcpy(neigh.mac, neighbor_reply->mac, ETH_ALEN);
    memcpy(&neigh.ip, &neighbor_reply->ip, sizeof(neigh.ip));

    return cache_get_neigh(&neigh);
}

int cache_neigh_update(struct netlink_neigh_cmd *neigh_cmd)
{
    int ret = 0;
    struct neigh_cache *cache;
    struct neigh_cache_key key;

    key.ifindex = neigh_cmd->ifindex;
    memcpy(&key.ip, &neigh_cmd->ip, sizeof(key.ip));

    cache = g_hash_table_lookup(db_neigh_cache, &key);
    if (!cache) {
        ret = -ENOENT;
        goto out;
    }

    // Update the MAC address
    if (!is_same_mac(cache->mac, neigh_cmd->mac))
        memcpy(cache->mac, neigh_cmd->mac, ETH_ALEN);

    if (neigh_cmd->nud_state != cache->nud_state) {
        cache->nud_state = neigh_cmd->nud_state;
        if (clock_gettime(CLOCK_REALTIME, &cache->times.updated) == -1) {
            pr_err(errno, "clock_gettime");
            ret = -errno;
            goto out;
        }
        cache->times.referenced = cache->times.updated;
        cache->update_count++;
    }

out:
    return ret;
}

void cache_del_neigh(struct neigh_cache *neigh)
{
    struct neigh_cache_key key;

    key.ifindex = neigh->ifindex;
    memcpy(&key.ip, &neigh->ip, sizeof(key.ip));

    g_hash_table_remove(db_neigh_cache, &key);
}

// Cache setup and cleanup functions
int setup_cache(void)
{
    db_lookup_vlan_networkid = g_hash_table_new_full(
        vlan_networkid_cache_key_hash, vlan_networkid_cache_key_equal,
        g_free, NULL);
    if (!db_lookup_vlan_networkid) {
        pr_err(errno, "g_hash_table_new");
        goto err0;
    }

    db_lookup_addr = g_hash_table_new_full(addr_cache_key_hash,
                                                addr_cache_key_equal,
                                                g_free, NULL);
    if (!db_lookup_addr) {
        pr_err(errno, "g_hash_table_new");
        goto err1;
    }

    db_lookup_addr_ifindex = g_hash_table_new_full(ifindex_addr_key_hash,
                                                   ifindex_addr_key_equal,
                                                   g_free, NULL);
    if (!db_lookup_addr_ifindex) {
        pr_err(errno, "g_hash_table_new");
        goto err2;
    }

    db_link_cache = g_hash_table_new(g_int_hash, g_int_equal);
    if (!db_link_cache) {
        pr_err(errno, "g_hash_table_new");
        goto err3;
    }

    db_network_cache = g_hash_table_new(g_int_hash, g_int_equal);
    if (!db_network_cache) {
        pr_err(errno, "g_hash_table_new");
        goto err4;
    }

    db_fdb_cache = g_hash_table_new_full(fdb_cache_key_hash, fdb_cache_key_equal,
                                    g_free, g_free);
    if (!db_fdb_cache) {
        pr_err(errno, "g_hash_table_new");
        goto err5;
    }

    db_neigh_cache = g_hash_table_new_full(neigh_cache_key_hash, neigh_cache_key_equal,
                                           g_free, g_free);
    if (!db_neigh_cache) {
        pr_err(errno, "g_hash_table_new");
        goto err6;
    }

    return 0;
err6:
    g_hash_table_destroy(db_fdb_cache);
err5:
    g_hash_table_destroy(db_network_cache);
err4:
    g_hash_table_destroy(db_link_cache);
err3:
    g_hash_table_destroy(db_lookup_addr_ifindex);
err2:
    g_hash_table_destroy(db_lookup_addr);
err1:
    g_hash_table_destroy(db_lookup_vlan_networkid);
err0:
    return -errno;
}

void cleanup_cache(void)
{
    if (db_lookup_vlan_networkid)
        g_hash_table_destroy(db_lookup_vlan_networkid);

    if (db_lookup_addr)
        g_hash_table_destroy(db_lookup_addr);

    if (db_lookup_addr_ifindex)
        g_hash_table_destroy(db_lookup_addr_ifindex);

    if (db_link_cache) {
        for (GList *iter = g_hash_table_get_values(db_link_cache);
             iter; iter = g_list_next(iter)) {
            cache_del_link(iter->data);
            g_free(iter->data);
        }
        g_hash_table_destroy(db_link_cache);
    }

    if (db_network_cache)
        g_hash_table_destroy(db_network_cache);

    if (db_fdb_cache)
        g_hash_table_destroy(db_fdb_cache);

    if (db_neigh_cache)
        g_hash_table_destroy(db_neigh_cache);
}
