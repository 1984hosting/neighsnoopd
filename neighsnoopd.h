/* SPDX-License-Identifier: GPL-2.0-or-later */
/* SPDX-FileCopyrightText: 2024 - 1984 Hosting Company <1984@1984.is> */
/* SPDX-FileCopyrightText: 2024 - Freyx Solutions <frey@freyx.com> */
/* SPDX-FileContributor: Freysteinn Alfredsson <freysteinn@freysteinn.com> */
/* SPDX-FileContributor: Julius Thor Bess Rikardsson <juliusbess@gmail.com> */

#ifndef NEIGHSNOOPD_H_
#define NEIGHSNOOPD_H_

#include <stdio.h>
#include <stdbool.h>
#include <glib.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <regex.h>
#include <bpf/libbpf.h>
#include <libmnl/libmnl.h>

#include "neighsnoopd_shared.h"

#define MAC_ADDR_STR_LEN 18

#define STATS_SOCKET_PATH "/run/neighsnoopd.sock"

struct env {
    int ifidx_mon;
    char ifidx_mon_str[IF_NAMESIZE];
    char *str_deny_filter;
    regex_t allow_filter;
    regex_t deny_filter;
    bool has_allow_filter;
    bool has_deny_filter;
    bool is_xdp;
    bool fail_on_qfilter_present;
    bool only_ipv4;
    bool only_ipv6;
    bool verbose;
    bool debug;
    bool has_count;
    int count;
    bool netlink;
    bool disable_ipv6ll_filter;

    // Event file descriptors
    int signal_fd;
    int nl_fd;
    int ringbuf_fd;
    int epoll_fd;
    int number_of_fds;

    int packet_fd; // AF_PACKET socket

    // BPF maps
    struct ring_buffer *ringbuf;
    int target_networks_fd;

    // Setup and Cleanup states
    struct neighsnoopd_bpf *skel;
    struct bpf_tc_hook tc_hook;
    struct bpf_tc_opts tc_opts;

    // Used in setup
    bool has_links;
    bool has_networks;
    bool has_fdb;
    __u32 link_seq; // Init sequence numbers
    __u32 addr_seq;
    __u32 fdb_seq;
};

struct nl_env {
    __u32 mnl_portid;
    struct mnl_socket *nl;
    __u32 nlm_seq;

    bool netlink_tx_in_progress;
    GList *netlink_tx_queue;
    int netlink_tx_queue_count;
    int netlink_tx_count;

    GList *netlink_cmd_queue;
    int netlink_cmd_count;
};

enum cmd_type {
    CMD_NONE,
    CMD_LINK_ADD,
    CMD_LINK_DEL,
    CMD_ADDR_ADD,
    CMD_ADDR_DEL,
    CMD_FDB_ADD,
    CMD_FDB_DEL,
    CMD_NEIGH_ADD,
    CMD_NEIGH_DEL
};

struct netlink_link_cmd {
    enum cmd_type cmd_type;
    char ifname[IF_NAMESIZE];
    __u8 mac[ETH_ALEN];
    char kind[128];
    char slave_kind[128];
    int ifindex;
    __u32 vlan_protocol;
    __u32 vlan_id;
    bool has_vlan;
    int link_ifindex;
    bool is_macvlan;
    bool is_vrf;
};

struct netlink_addr_cmd {
    enum cmd_type cmd_type;
    int ifindex;
    struct in6_addr ip;
    struct in6_addr network;
    int prefixlen;
    int true_prefixlen;
    int flags;
};

struct netlink_neigh_cmd {
    enum cmd_type cmd_type;
    __u8 mac[ETH_ALEN];
    int ifindex;
    __u32 vlan_id;

    int family;
    int nud_state;
    int type;
    struct in6_addr ip;
    bool is_externally_learned;
    bool has_ip;
};

union netlink_cmd {
    enum cmd_type cmd_type;
    struct netlink_link_cmd link;
    struct netlink_addr_cmd addr;
    struct netlink_neigh_cmd neigh;
};

struct link_cache {
    __u32 ifindex;
    __u32 link_ifindex;
    char ifname[IF_NAMESIZE];
    __u8 mac[ETH_ALEN];
    char kind[128];
    char slave_kind[128];
    __u32 vlan_protocol;
    __u32 vlan_id;
    bool has_vlan;
    GList *network_list; // link_network_cache entries
    GList *fdb_list;
    GList *neigh_list;
    bool is_svi;
    bool is_macvlan;
    bool ignore_link;

    int reference_count;
    struct {
        struct timespec created;
        struct timespec updated;
        struct timespec referenced;
    } times;
};

struct network_cache {
    __u32 id;
    struct in6_addr network;
    char network_str[INET6_ADDRSTRLEN];
    int prefixlen;
    int true_prefixlen;
    GList *links; // link_network_cache entries
    int refcnt;

    int reference_count;
    struct {
        struct timespec created;
        struct timespec referenced;
    } times;
};

struct link_network_cache {
    struct in6_addr ip;
    struct network_cache *network;
    struct link_cache *link;
};

// Used to lookup network_link_cache
struct vlan_networkid_cache_key {
    __u32 network_id;
    __u32 vlan_id;
};

// Used to lookup link_network_cache
struct ifindex_addr_cache_key {
    __u32 ifindex;
    struct in6_addr network_ip;
};

struct fdb_cache_key {
    __u8 mac[ETH_ALEN];
    __u32 ifindex;
    __u32 vlan_id;
};

// The fdb_cache is only used to check if an address is externally learned
struct fdb_cache {
    __u8 mac[ETH_ALEN];
    __u8 mac_str[MAC_ADDR_STR_LEN];
    struct link_cache *link;
    __u32 vlan_id;

    int reference_count;
    struct {
        struct timespec created;
        struct timespec referenced;
    } times;
};

struct neigh_cache_key {
    __u32 ifindex;
    struct in6_addr ip;
};

struct neigh_cache {
    __u8 mac[ETH_ALEN];
    __u8 mac_str[MAC_ADDR_STR_LEN];
    __u32 ifindex; // Used for debugging
    struct link_network_cache *sending_link_network;
    int type;
    struct in6_addr ip;
    char ip_str[INET6_ADDRSTRLEN];
    int nud_state;

    int update_count;
    int reference_count;
    struct {
        struct timespec created;
        struct timespec updated;
        struct timespec referenced;
    } times;
};

enum cache_reference {
    CACHE_NO_REFERENCE,
    CACHE_REFERENCE,
};

void mac_to_string(__u8 *buffer, const __u8 *mac, size_t buffer_size);
bool is_zero_mac(const __u8 *mac);
bool is_same_mac(const __u8 *mac1, const __u8 *mac2);
void calculate_network_address(const struct in6_addr *ip,
                               const struct in6_addr *netmask,
                               struct in6_addr *network);
struct in6_addr calculate_network_using_cidr(const struct in6_addr *ip,
                                               int cidr);
int compare_ipv6_addresses(const struct in6_addr *addr1,
                           const struct in6_addr *addr2);
int format_ip_address(char *buf, size_t size,
                             const struct in6_addr *addr);
int format_ip_address_cidr(char *buf, size_t size, const struct in6_addr *addr,
                        int cidr);
int calculate_cidr(const struct in6_addr *addr);
struct timespec get_time(void);

// Print functions
void __pr_std(FILE * file, const char *format, ...);

// Print functions for Netlink messages
int pr_nl_attr_neigh(const struct nlattr *attr, void *data);
int pr_nl_neigh_ndm(const struct nlmsghdr *nlh);
int pr_nl_attr(const struct nlattr *attr, void *data);
int pr_nl_ndm(const struct nlmsghdr *nlh);
void pr_nl_nlmsg(struct nlmsghdr *nlh, size_t num_bytes);

// Netlink functions
int netlink_process_rx_queue(void);
union netlink_cmd *netlink_dequeue_cmd(void);
int netlink_parse_neigh_attr_cb(const struct nlattr *attr, void *data);
int netlink_handle_neigh_cb(const struct nlmsghdr *nlh, void *data);
int netlink_parse_addr_attr_cb(const struct nlattr *attr, void *data);
int netlink_handle_addr_cb(const struct nlmsghdr *nlh, void *data);
int netlink_parse_link_attr_cb(const struct nlattr *attr, void *data);
int netlink_handle_link_cb(const struct nlmsghdr *nlh, void *data);
int netlink_handle_all_cb(const struct nlmsghdr *nlh, void *data);
int netlink_get_interfaces(void);
int netlink_get_addresses(void);
int netlink_get_fdb(void);
int netlink_get_neighs(int family);
int netlink_send_neigh(struct neighbor_reply *reply, int ifindex);
int netlink_queue_add(struct nlmsghdr *nlh);
struct nlmsghdr *netlink_queue_peek(void);
struct nlmsghdr *netlink_queue_pop(void);
int netlink_queue_send(struct nlmsghdr *nlh);
int netlink_queue_send_next();
void netlink_queue_check_ack_tx_queue(const struct nlmsghdr *nlh);
void netlink_cmd_free(union netlink_cmd *cmd);
int setup_netlink(void);
void cleanup_netlink(void);

// Cache functions
struct link_cache *cache_add_link(struct netlink_link_cmd *link);
int cache_update_link(struct link_cache *cache,
                             struct netlink_link_cmd *link_cmd);
int cache_add_link_network(struct link_network_cache *link_network);
struct link_cache *cache_get_link(__u32 ifindex);
int cache_del_link(struct netlink_link_cmd *link);
struct link_network_cache *cache_new_link_network(void);
struct link_network_cache *cache_get_link_network_by_reply(
    struct neighbor_reply *neighbor_reply);
struct link_network_cache *cache_get_link_network_by_addr(
    struct link_cache *link, struct in6_addr *ip);
struct link_network_cache *cache_get_link_network(int ifindex,
                                                  struct in6_addr network_ip);
struct network_cache *cache_add_network(struct netlink_addr_cmd *addr);
struct network_cache *cache_get_network_by_id(__u32 network_id);
struct network_cache *cache_get_network(struct netlink_addr_cmd *cmd);
int cache_del_network(struct netlink_addr_cmd *addr);
struct fdb_cache *cache_get_fdb(struct netlink_neigh_cmd *neigh);
struct fdb_cache *cache_get_fdb_by_reply(struct neighbor_reply *neighbor_reply,
                                         int ifindex);
struct fdb_cache *cache_add_fdb(struct netlink_neigh_cmd *neigh);
int cache_del_fdb(struct netlink_neigh_cmd *neigh);
struct neigh_cache *cache_add_neigh(struct link_network_cache *link_network,
                                    struct netlink_neigh_cmd *neigh_cmd);
struct neigh_cache *cache_get_neigh(struct netlink_neigh_cmd *neigh);
struct neigh_cache *cache_get_neigh_by_reply(struct neighbor_reply *neighbor_reply,
                                             int ifindex);
int cache_neigh_update(struct netlink_neigh_cmd *neigh);
void cache_del_neigh(struct neigh_cache *neigh);
int setup_cache(void);
void cleanup_cache(void);


// Prints info messages
#define pr_info(fmt, ...)                              \
    do {                                               \
        __pr_std(stdout, "INFO: " fmt, ##__VA_ARGS__); \
    } while (0)

// Print error message with error string
#define __pr_err(err, fmt, ...)                                           \
    do {                                                                  \
        if (err == 0)                                                     \
            __pr_std(stderr, fmt "\n", ##__VA_ARGS__);                    \
        else                                                              \
            __pr_std(stderr, fmt ": %s\n", ##__VA_ARGS__, strerror(err)); \
    } while (0)

// Prints error messages with function and line number
#define pr_err(err, fmt, ...)                                          \
    do {                                                               \
        __pr_err(err, "ERROR: [%-13.13s: %-10.10s:%d] " fmt, __FILE__, \
                 __func__, __LINE__,                                   \
                 ##__VA_ARGS__);                                       \
    } while (0)


// The pr_debug function prints debug messages if the debug flag is set
#define __pr_debug(fmt, ...)                  \
    do {                                      \
        if (!env.debug)                       \
            break;                            \
        __pr_std(stderr, fmt, ##__VA_ARGS__); \
    } while (0)

// Prints debug messages with function and line number
#define pr_debug(fmt, ...)                                                    \
    do {                                                                      \
        __pr_debug("DEBUG: [%-13.13s: %-10.10s:%d] " fmt, __FILE__, __func__, \
                   __LINE__, ##__VA_ARGS__);                                  \
    } while (0)

// Prints netlink messages wihout prefix
#define __pr_nl(fmt, ...)                     \
    do {                                      \
        if (!env.netlink)                     \
            break;                            \
        __pr_std(stderr, fmt, ##__VA_ARGS__); \
    } while (0)


// Prints netlink messages with function and line number
#define pr_nl(fmt, ...)                                                      \
    do {                                                                     \
        __pr_nl("NETLINK: [%-13.13s: %-10.10s:%d] " fmt, __FILE__, __func__, \
                __LINE__,                                                    \
                ##__VA_ARGS__);                                              \
    } while (0)

#endif // NEIGHSNOOPD_H_
