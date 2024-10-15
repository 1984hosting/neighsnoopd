/* SPDX-License-Identifier: GPL-2.0-or-later */
/* SPDX-FileCopyrightText: 2024 - 1984 Hosting Company <1984@1984.is> */
/* SPDX-FileCopyrightText: 2024 - Freyx Solutions <frey@freyx.com> */
/* SPDX-FileContributor: Freysteinn Alfredsson <freysteinn@freysteinn.com> */
/* SPDX-FileContributor: Julius Thor Bess Rikardsson <juliusbess@gmail.com> */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <signal.h>
#include <argp.h>
#include <time.h>
#include <ifaddrs.h>
#include <regex.h>
#include <string.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <linux/if_ether.h>

#include <libmnl/libmnl.h>
#include <linux/rtnetlink.h>

#include "neighsnoopd.h"

#include "neighsnoopd_shared.h" // Shared struct neighbor_reply with BPF
#include "neighsnoopd.bpf.skel.h"

#include "version.in.h"

struct env env = {0};

struct lookup_cache {
    struct neighbor_reply *neighbor_reply;
    __u8 mac_str[MAC_ADDR_STR_LEN];
    __u32 ifindex;
    char ifname[IFNAMSIZ];
    __u32 link_ifindex;
    char kind[128];
    char ip_str[INET6_ADDRSTRLEN];
    __u32 cidr;

    // FDB
    bool is_ext_learned;
    bool is_macvlan;

    // Debug information for debug mode only
    struct {
        char network_str[INET6_ADDRSTRLEN];
    } debug;
};

static volatile sig_atomic_t exiting = 0;

static __u32 nlm_seq;
struct mnl_socket *nl;
__u32 mnl_portid;

const char *argp_program_version = "neighsnoopd v0.9\n"
    "Build date: " __DATE__ " " __TIME__ "\n" \
    "git commit: " GIT_COMMIT;

const char *argp_program_bug_address =
        "https://github.com/1984hosting/neighsnoopd";

const char argp_program_doc[] =
    "Listens for ARP and NA replies and adds the neighbor to the Neighbors"
    "table.\n";

static const struct argp_option opts[] = {
    { "ipv4", '4', NULL, 0, "Only handle IPv4 ARP Reply packets", 0 },
    { "ipv6", '6', NULL, 0, "Only handle IPv6 NA packets", 0 },
    { "count", 'c', "NUM", 0, "This option handles a fixed number of ARP or NA"
      "replies before terminating the program."
      "Use this for debugging purposes only", 0 },
    { "filter", 'f', "REGEXP", 0,
      "Filters out interfaces with a regular expression exclude from adding to"
      "the neighbor cache. Example: -f '^br0|.*-v0^'", 0 },
    { "macvlan", 'm', NULL, 0, "Disable filtering macvlan devices from being"
      "added to the neighbor cache.", 0 },
    { "no-qfilter-present", 'q', NULL, 0, "Do not replace the present Qdisc"
      "filter if it is present on the Ingress device", 0 },
    { "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
    { "xdp", 'x', NULL, 0, "Attach XDP instead of TC. This option only works"
      "on devices with a VLAN header on the packets available to XDP.", 0},
    { "disable_ipv6ll_filter", 'l', NULL, 0,
      "Disable the default IPv6 link-local filter", 0},
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
    {},
};

static int add_neigh(struct lookup_cache *cache)
{
    int err = -1; // the default return value is an error

    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    struct ndmsg *ndm;
    struct in6_addr *addr = &cache->neighbor_reply->ip;
    int ret;

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = RTM_NEWNEIGH;
    if (cache->neighbor_reply->in_family == AF_INET6)
        nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK;
    else
        nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK | NLM_F_EXCL;
    nlh->nlmsg_seq = ++nlm_seq;

    ndm = mnl_nlmsg_put_extra_header(nlh, sizeof(*ndm));
    ndm->ndm_family = cache->neighbor_reply->in_family;
    ndm->ndm_state = NUD_REACHABLE;
    ndm->ndm_ifindex = cache->ifindex;

    // Add IP address
    if (IN6_IS_ADDR_V4MAPPED(addr)) {
        struct in_addr ipv4_addr;
        memcpy(&ipv4_addr, &addr->s6_addr[12], sizeof(ipv4_addr));
        mnl_attr_put(nlh, NDA_DST, sizeof(ipv4_addr), &ipv4_addr);
    } else {
        mnl_attr_put(nlh, NDA_DST, sizeof(*addr), addr);
    }

    // Add MAC address
    mnl_attr_put(nlh, NDA_LLADDR, sizeof(cache->neighbor_reply->mac),
                 cache->neighbor_reply->mac);

    // Add VLAN information if needed
    if (cache->neighbor_reply->vlan_id > 0)
        mnl_attr_put(nlh, NDA_VLAN, sizeof(cache->neighbor_reply->vlan_id),
                     &cache->neighbor_reply->vlan_id);

    pr_debug("Requesting to add neighbor:\n");
    pr_debug("- Interface %d: %s\n", cache->ifindex, cache->ifname);
    pr_debug("- IP address: %s\n", cache->ip_str);
    pr_debug("- MAC address: %s\n", cache->mac_str);

    pr_nl("Sending netlink message\n");
    pr_nl_nlmsg(nlh, nlm_seq);

    // Send Netlink request update neigh table
    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        pr_err(errno, "mnl_socket_sendto");
        goto out;
    }

    // Parse the response
    ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    if (ret < 0) {
        pr_err(errno, "mnl_socket_recvfrom");
        goto out;
    }

    pr_nl("Received netlink message\n");
    pr_nl_nlmsg((struct nlmsghdr *)buf, nlm_seq);

    err = mnl_cb_run(buf, ret, nlm_seq, mnl_portid,
                     NULL, NULL);
    if (err < MNL_CB_STOP) {
        if (errno == EEXIST) {
            pr_debug("Neighbor already exists in the cache\n");
            goto out;
        }
        pr_err(errno, "Failed to parse Netlink message");
        goto out;
    }

    err = 0; // Success
    pr_info("Added MAC: %s IP: %s/%d to FDB on interface: %s\n",
            cache->mac_str, cache->ip_str, cache->cidr, cache->ifname);

out:
    return err;
}

static bool filter_interfaces(char *ifname)
{
    int ret;
    if (!env.has_filter)
        return false;

    ret = regexec(&env.regex_filter, ifname, 0, NULL, 0);
    if (ret)
        return false;

    pr_debug("Filtered interface %s using filter: '%s'\n", ifname,
             env.regexp_filter_ifname);
    return true;
}

static int netlink_recv(struct nlmsghdr *nlh, char *buf, size_t buf_size,
                        mnl_cb_t parse_nlm_func,
                        struct lookup_cache *cache)
{
    int ret;

    pr_nl("sending netlink message\n");
    pr_nl_nlmsg(nlh, nlm_seq);

    // Send Netlink request to fetch FDB entries
    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        pr_err(errno, "mnl_socket_sendto");
        return false;
    }

    // Parse the response
    while ((ret = mnl_socket_recvfrom(nl, buf, buf_size)) > 0) {
        pr_nl("received netlink message\n");
        pr_nl_nlmsg((struct nlmsghdr *)buf, nlm_seq);


        ret = mnl_cb_run(buf, ret, nlm_seq, mnl_portid, parse_nlm_func,
                         cache);

        if (nlh->nlmsg_type == NLMSG_DONE)
            break;

        if (nlh->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
            if (err->error != 0)
                pr_err(err->error, "Netlink error");

            break;
        }

        if (ret < MNL_CB_STOP) {
            pr_err(errno, "Failed to parse Netlink message");
            break;
        }
    }

    return ret;
}

static int parse_nlm(const struct nlmsghdr *nlh, size_t nlm_len,
                     mnl_attr_cb_t parse_nlm_attr_func,
                     const struct nlattr **tb, void *data)
{
    mnl_attr_parse(nlh, nlm_len, parse_nlm_attr_func, tb);

    if (nlh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
        if (err->error != 0)
            pr_err(err->error, "Netlink error");
        return MNL_CB_STOP;
    }

    if (nlh->nlmsg_type == NLMSG_DONE)
        return MNL_CB_STOP;

    return MNL_CB_OK;
}

// Extract information about an ifindex using Netlink
static int getlink_parse_attr_cb(const struct nlattr *attr, void *data)
{
    const struct nlattr **tb = data;
    int type = mnl_attr_get_type(attr);

    /* skip unsupported attribute in user-space */
    if (mnl_attr_type_valid(attr, IFLA_MAX) < 0)
        return MNL_CB_OK;

    switch(type) {
        case IFLA_LINK:
            if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
                pr_err(errno, "mnl_attr_validate");
                return MNL_CB_ERROR;
            }
            break;
        case IFLA_LINKINFO:
            if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
                pr_err(errno, "mnl_attr_validate");
                return MNL_CB_ERROR;
            }
    }
    tb[type] = attr;
    return MNL_CB_OK;
}

static int getlink_parse_nlm_cb(const struct nlmsghdr *nlh, void *data)
{
    struct ifinfomsg *ifm = mnl_nlmsg_get_payload(nlh);
    struct lookup_cache *cache = data;
    struct nlattr *tb[IFLA_MAX + 1] = {};

    if (nlh->nlmsg_type != RTM_NEWLINK) {
        pr_err(0, "Unexpected Netlink message type %d, expected %d",
               nlh->nlmsg_type, RTM_NEWLINK);
        return MNL_CB_STOP;
    }

    int ret = parse_nlm(nlh, sizeof(*ifm), getlink_parse_attr_cb,
                  (const struct nlattr **) tb, tb);
    if (ret < 0)
        return ret;

    // Add attributes to cache
    if (tb[IFLA_LINK])
        cache->link_ifindex = mnl_attr_get_u32(tb[IFLA_LINK]);

    if (tb[IFLA_LINKINFO]) {
        struct nlattr *link_attr;
        mnl_attr_for_each_nested(link_attr, tb[IFLA_LINKINFO]) {
            if (mnl_attr_get_type(link_attr) == IFLA_INFO_KIND) {

                snprintf(cache->kind, sizeof(cache->kind), "%s",
                         mnl_attr_get_str(link_attr));
            }
        }
    }

    if (strcmp(cache->kind, "macvlan") == 0)
        cache->is_macvlan = true;

    return MNL_CB_OK;
}

static bool probe_ifindex(struct lookup_cache *cache)
{
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    struct ifinfomsg *ifm;
    int ret;

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = RTM_GETLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = ++nlm_seq;

    ifm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
    ifm->ifi_family = AF_UNSPEC;
    ifm->ifi_index = cache->ifindex;

    ret = netlink_recv(nlh, buf, sizeof(buf), getlink_parse_nlm_cb, cache);

    if (ret < 0) {
        pr_err(errno, "Failed to lookup interface %s", cache->ifname);
        return false;
    }

    pr_debug("Device %d is of type: %s\n", cache->ifindex, strlen(
                 cache->kind) ? cache->kind : "unknown");
    return true;
}

// Extract information from the FDB using Netlink
static int getneigh_parse_attr_cb(const struct nlattr *attr, void *data)
{
    const struct nlattr **tb = data;
    int type = mnl_attr_get_type(attr);

    /* skip unsupported attribute in user-space */
    if (mnl_attr_type_valid(attr, NDA_MAX) < 0)
        return MNL_CB_OK;

    switch(type) {
    case NDA_DST:
    case NDA_LLADDR:
        if (mnl_attr_validate(attr, MNL_TYPE_BINARY) < 0) {
            pr_err(errno, "mnl_attr_validate");
            return MNL_CB_ERROR;
        }
        break;
    }
    tb[type] = attr;
    return MNL_CB_OK;
}

static int getneigh_parse_nlm_cb(const struct nlmsghdr *nlh, void *data)
{
    struct lookup_cache *cache = data;
    struct ndmsg *ndm = mnl_nlmsg_get_payload(nlh);
    struct nlattr *tb[NDA_MAX + 1] = {};
    const __u8 *fdb_mac = NULL;

    if (nlh->nlmsg_type != RTM_NEWNEIGH) {
        pr_err(0, "Unexpected Netlink message type %d, expected %d",
               nlh->nlmsg_type, RTM_NEWNEIGH);
        return MNL_CB_STOP;
    }

    if (parse_nlm(nlh, sizeof(*ndm), getneigh_parse_attr_cb,
                  (const struct nlattr **) tb, cache) < 0)
        return MNL_CB_STOP;

    if (tb[NDA_LLADDR] == NULL)
        return MNL_CB_OK;

    fdb_mac = mnl_attr_get_payload(tb[NDA_LLADDR]);
    if (memcmp(fdb_mac, cache->neighbor_reply->mac,
               sizeof(cache->neighbor_reply->mac)) != 0)
        return MNL_CB_OK;

    // Add attributes to cache
    if (ndm->ndm_flags & NTF_EXT_LEARNED)
        cache->is_ext_learned = true;

    return MNL_CB_OK;
}

static bool probe_fdb(struct lookup_cache *cache)
{
    // Query the FDB entries in AF_BRIDGE for the specified MAC address
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    struct ndmsg *ndm;
    int ret;

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = RTM_GETNEIGH;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;
    nlh->nlmsg_seq = ++nlm_seq;

    ndm = mnl_nlmsg_put_extra_header(nlh, sizeof(*ndm));
    ndm->ndm_family = AF_BRIDGE;

    ret = netlink_recv(nlh, buf, sizeof(buf), getneigh_parse_nlm_cb, cache);

    if (ret < 0) {
        pr_err(errno, "Failed lookup FDB");
        return false;
    }

    return true;
}

static bool find_ifindex_from_ip(struct lookup_cache *cache)
{
    struct ifaddrs *ifaddr, *ifa;
    struct sockaddr_in6 *addr6, *netmask6;
    struct sockaddr_in *addr4, *netmask4;
    struct in6_addr addr, netmask;
    struct in6_addr *given_ip = &cache->neighbor_reply->ip;
    struct in6_addr given_ip_network, network;
    const char* matching_ifname = NULL;
    __u32 matching_ifindex;

    if (getifaddrs(&ifaddr) == -1)
        goto err1;

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        struct lookup_cache getlink_cache = *cache;
        if (ifa->ifa_addr == NULL || ifa->ifa_netmask == NULL)
            continue;

        // Map legacy IPv4 addresses to IPv6
        if (ifa->ifa_addr->sa_family == AF_INET) {
            // Handle IPv4 to IPv6 mapping
            addr4 = (struct sockaddr_in *)ifa->ifa_addr;
            netmask4 = (struct sockaddr_in *)ifa->ifa_netmask;
            map_ipv4_to_ipv6(&addr, addr4->sin_addr.s_addr);
            map_ipv4_to_ipv6(&netmask, netmask4->sin_addr.s_addr);
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
            // Handle IPv6 addresses
            addr6 = (struct sockaddr_in6 *)ifa->ifa_addr;
            netmask6 = (struct sockaddr_in6 *)ifa->ifa_netmask;
            addr = addr6->sin6_addr;
            netmask = netmask6->sin6_addr;
        } else { // Ignore unknown address families
            continue;
        }

        // Calculate the network address
        calculate_network_address(&addr, &netmask, &network);
        calculate_network_address(given_ip, &netmask, &given_ip_network);

        // Compare the network addresses
        if (!compare_ipv6_addresses(&network, &given_ip_network))
            continue;

        getlink_cache.ifindex = if_nametoindex(ifa->ifa_name);
        if (!getlink_cache.ifindex) {
            pr_err(errno, "if_nametoindex");
            continue;
        }

        probe_ifindex(&getlink_cache);

        if (getlink_cache.link_ifindex == 0)
            continue;

        if (getlink_cache.link_ifindex != env.ifidx_mon) {
            pr_debug("Skipping interface %d because it isn't directly"
                     "connected to %d\n", getlink_cache.link_ifindex,
                     env.ifidx_mon);
            continue;
        }

        matching_ifname = ifa->ifa_name;
        *cache = getlink_cache;
        break; // Found a matching interface
    }

    if (!matching_ifname) {
        pr_debug("No interface found for IP: %s\n", cache->ip_str);
        goto err2;
    }

    matching_ifindex = if_nametoindex(matching_ifname);
    if (!matching_ifindex) {
        pr_err(errno, "if_nametoindex");
        goto err2;
    }

    memcpy(cache->ifname, matching_ifname, sizeof(cache->ifname));
    cache->ifindex = matching_ifindex;

    cache->cidr = calculate_cidr(&netmask);

    if (env.debug) {
        if (format_ip_address(cache->debug.network_str,
                              sizeof(cache->debug.network_str), &network)) {
            pr_err(errno, "format_ip_address");
            goto err2;
        }
        pr_debug("Found IP: %s in %s/%d on %s linked to %s\n",
                 cache->ip_str,
                 cache->debug.network_str,
                 cache->cidr,
                 cache->ifname,
                 env.ifidx_mon_str);
    }
    return true;
err2:
    freeifaddrs(ifaddr);
err1:
    return false;
}

// Callback function to handle data from the ring buffer
static int handle_neighbor_reply(void *ctx, void *data, size_t data_sz)
{
    struct lookup_cache cache = {0};
    cache.neighbor_reply = (struct neighbor_reply *)data;

    if (env.only_ipv6 && cache.neighbor_reply->in_family != AF_INET6)
        return 1;
    else if (env.only_ipv4 && cache.neighbor_reply->in_family != AF_INET)
        return 1;

    env.count--;

    pr_debug("Received Neighbor Reply\n");

    mac_to_string(cache.mac_str, cache.neighbor_reply->mac,
                  sizeof(cache.mac_str));

    if (format_ip_address(cache.ip_str, sizeof(cache.ip_str),
                          &cache.neighbor_reply->ip)) {
        pr_err(errno, "format_ip_address");
        return 1;
    }

    pr_debug("Received Neighbor Reply MAC: %s - IP: %s\n", cache.mac_str,
             cache.ip_str);

    if (!env.disable_ipv6ll_filter &
        (cache.neighbor_reply->in_family == AF_INET6)) {
        if (IN6_IS_ADDR_LINKLOCAL(&cache.neighbor_reply->ip)) {
            pr_debug("Neighbor IP '%s' is IPv6 link-local: filtered\n", cache.ip_str);
            return 1;
        }
    }

    if (!find_ifindex_from_ip(&cache)) {
        pr_debug("No interface mached destination: filtered\n");
        return 1;
    }

    if (filter_interfaces(cache.ifname)) {
        pr_debug("Interface '%s' matches regexp filter: filtered\n",
                 cache.ifname);
        return 1;
    }

    if (cache.is_macvlan && !env.disable_macvlan_filter) {
        pr_debug("Interface '%s' is a macvlan: filtered\n", cache.ifname);
        return 1;
    }

    probe_fdb(&cache);
    if (cache.is_ext_learned) {
        pr_debug("MAC address is not connected locally: filtered\n");
        return 1;
    }

    pr_debug("MAC is locally connected. Adding neighbor.\n");
    if (add_neigh(&cache))
        return 1;

    // Success
    return 0;
}

static void sig_handler(int sig)
{
    exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG && !env.debug)
        return 0;
    return vfprintf(stderr, format, args);
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    static int pos_args;

    switch (key) {
        case 'h':
            argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
            break;
        case '4':
            if (env.only_ipv6) {
                fprintf(stderr, "Cannot specify both --ipv4 and --ipv6\n");
                argp_usage(state);
                exit(EXIT_FAILURE);
            }
            env.only_ipv4 = true;
            break;
        case '6':
            if (env.only_ipv4) {
                fprintf(stderr, "Cannot specify both --ipv4 and --ipv6\n");
                argp_usage(state);
                exit(EXIT_FAILURE);
            }
            env.only_ipv6 = true;
            break;
        case 'c':
            env.has_count = true;
            env.count = strtoul(arg, NULL, 0);
            if (env.count == 0) {
                perror("Invalid count");
                argp_usage(state);
                exit(EXIT_FAILURE);
            }
            break;
        case 'f':
            if (strlen(arg) == 0) {
                fprintf(stderr, "Invalid filter\n");
                argp_usage(state);
                exit(EXIT_FAILURE);
            }
            env.regexp_filter_ifname = arg;
            env.has_filter = true;
            break;
        case 'm':
            env.disable_macvlan_filter = true;
            break;
        case 'q':
            env.fail_on_qfilter_present = true;
            break;
        case 'v':
            if (env.debug)
                env.netlink = true;
            if (env.verbose)
                env.debug = true;
            env.verbose = true;
            break;
        case 'x':
            env.is_xdp = true;
            break;
        case ARGP_KEY_NO_ARGS:
            fprintf(stderr, "Missing network device <IFNAME_MON>\n");
            argp_usage(state);
            break;
        case ARGP_KEY_ARG:
            if (pos_args > 0) {
                fprintf(stderr, "Too many arguments: %s\n", arg);
                argp_usage(state);
                exit(EXIT_FAILURE);
            }
            env.ifidx_mon = if_nametoindex(arg);
            if (!env.ifidx_mon) {
                perror("Invalid network device");
                argp_usage(state);
                exit(EXIT_FAILURE);
            }
            strncpy(env.ifidx_mon_str, arg, sizeof(env.ifidx_mon_str));
            pos_args++;
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
// This function is references by argp and not from this code
static void short_usage(FILE *fp, struct argp_state *state)
{
    fprintf(stderr, "Usage: %s [--help] [--verbose] <IFNAME_MON>\n",
            state->argv[0]);
}
#pragma GCC diagnostic pop

int main(int argc, char **argv)
{
    struct neighsnoopd_bpf *skel;
    int err;
    static const struct argp argp = {
        .options = opts,
        .parser = parse_arg,
        .doc = argp_program_doc,
        .args_doc = "<IFNAME_MON>",
    };

    nlm_seq = time(NULL);

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        goto cleanup1;

    err = 0;
    if (env.has_filter)
        err = regcomp(&env.regex_filter, env.regexp_filter_ifname, REG_EXTENDED);

    if (err) {
        fprintf(stderr, "Could not compile regex");
        goto cleanup1;
    }

    libbpf_set_print(libbpf_print_fn);

    nl = mnl_socket_open(NETLINK_ROUTE);
    if (nl == NULL) {
        err = errno;
        perror("mnl_socket_open");
        goto cleanup1;
    }
    mnl_portid = mnl_socket_get_portid(nl);
    pr_nl("MNL port ID: %d\n", mnl_portid);

    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        err = -errno;
        perror("mnl_socket_bind");
        goto cleanup2;
    }

    // Open the skeleton
    skel = neighsnoopd_bpf__open();
    if (!skel) {
        perror("Failed to open BPF skeleton\n");
        err = EXIT_FAILURE;
        goto cleanup2;
    }

    err = neighsnoopd_bpf__load(skel);
    if (err) {
        perror("Failed to load BPF skeleton\n");
        err = EXIT_FAILURE;
        goto cleanup2;
    }

    // XDP
    struct bpf_link *xdp_link;

    // TC OPTS
    LIBBPF_OPTS(bpf_tc_hook, tc_hook,
                .ifindex = env.ifidx_mon,
                .attach_point = BPF_TC_INGRESS);
    LIBBPF_OPTS(bpf_tc_opts, tc_opts,
                .handle = 1,
                .priority = 1,
                .prog_fd = bpf_program__fd(
                    skel->progs.handle_neighbor_reply_tc));

    if (!env.fail_on_qfilter_present)
        tc_opts.flags |= BPF_TC_F_REPLACE;

    bool hook_created = false;
    if (env.is_xdp) {
        // attach xdp program to interface
        xdp_link = bpf_program__attach_xdp(
            skel->progs.handle_neighbor_reply_xdp, env.ifidx_mon);
        if (!xdp_link) {
            perror("Failed to attach XDP hook");
            goto cleanup3;
        }
    } else {
        // Load TC hook instead of XDP
        // Attach the BPF program to the clsact qdisc for ingress

        /*
         * The TC Qdisc hook may already exist because:
         * 1. Other processes or users create it.
         * 2. By attaching to the TC ingress, the bpf_tc_hook_destroy does not
         * remove the Qdisc and may leave an egress filter in place since the last
         * invocation of the program.
         */
        err = bpf_tc_hook_create(&tc_hook);
        if (!err)
            hook_created = true;
        if (err && err != -EEXIST)
            goto cleanup3;

        if (bpf_tc_attach(&tc_hook, &tc_opts))
            goto cleanup4;
    }

    // Parse Neighbor replies
    struct bpf_map *ringbuf_map =
        bpf_object__find_map_by_name(skel->obj, "neighbor_ringbuf");

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(ringbuf_map),
                                              handle_neighbor_reply, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer");
        goto cleanup5;
    }

    if (signal(SIGINT, sig_handler) == SIG_ERR) {
        err = errno;
        perror("Can't set signal handler");
        goto cleanup6;
    }

    // Main loop
    while (!exiting) {
        int err = ring_buffer__poll(rb, -1);
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer");
            break;
        }
        if (env.has_count && env.count == 0)
            break;
    }
    err = 0;

    // Cleanup
cleanup6:
    ring_buffer__free(rb);
    close(bpf_map__fd(ringbuf_map));
cleanup5:
    tc_opts.flags = tc_opts.prog_fd = tc_opts.prog_id = 0;
    if (!env.is_xdp) {
        pr_debug("Detaching the TC hook\n");
        err = bpf_tc_detach(&tc_hook, &tc_opts);
        if (err)
            perror("Failed to detach TC hook\n");
    }
cleanup4:
    if (hook_created) {
        pr_debug("Destroying the TC hook\n");
        err = bpf_tc_hook_destroy(&tc_hook);
        if (err)
            perror("Failed to destroy TC hook");
    }
cleanup3:
    neighsnoopd_bpf__destroy(skel);
cleanup2:
    mnl_socket_close(nl);
cleanup1:
    return -err;
}
