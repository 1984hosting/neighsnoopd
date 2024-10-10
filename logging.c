/* SPDX-License-Identifier: GPL-2.0-or-later */
/* SPDX-FileCopyrightText: 2024 - 1984 Hosting Company <1984@1984.is> */
/* SPDX-FileCopyrightText: 2024 - Freyx Solutions <frey@freyx.com> */
/* SPDX-FileContributor: Freysteinn Alfredsson <freysteinn@freysteinn.com> */
/* SPDX-FileContributor: Julius Thor Bess Rikardsson <juliusbess@gmail.com> */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/rtnetlink.h>
#include <libmnl/libmnl.h>

#include "neighsnoopd.h"

extern struct env env;
extern struct nl_env nl_env;

void __pr_std(FILE * file, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vfprintf(file, format, args);
    va_end(args);
}

int pr_nl_attr_link(const struct nlattr *attr, void *data)
{
    int type = mnl_attr_get_type(attr);
    char ip_str[INET6_ADDRSTRLEN];
    const char *ifname;
    const unsigned char *addr;
    const unsigned char *broadcast;
    uint32_t mtu;
    uint8_t operstate;
    uint8_t linkmode;
    uint32_t link;
    const struct rtnl_link_stats *stats;
    const char *qdisc;
    uint8_t carrier;
    uint32_t master;
    uint32_t num_tx_queues;
    uint32_t num_rx_queues;
    struct nlattr *nested_attr;
    int nested_type;
    const char *kind;
    uint32_t gso_max_segs;
    uint32_t gso_max_size;

    // Print the basic info of the attribute
    __pr_nl(">  [ATTR %d] %d octets", type, mnl_attr_get_len(attr));

    switch (type) {
        case IFLA_IFNAME:
            ifname = mnl_attr_get_str(attr);
            __pr_nl(" <IFNAME> %s", ifname);
            break;
        case IFLA_ADDRESS:
            addr = mnl_attr_get_payload(attr);
            format_ip_address(ip_str, sizeof(ip_str), (struct in6_addr *)addr);
            __pr_nl(" <ADDRESS> %s", ip_str);
            break;
        case IFLA_BROADCAST:
            broadcast = mnl_attr_get_payload(attr);
            __pr_nl(" <BROADCAST> %02x:%02x:%02x:%02x:%02x:%02x",
                    broadcast[0], broadcast[1], broadcast[2], broadcast[3],
                    broadcast[4], broadcast[5]);
            break;
        case IFLA_MTU:
            mtu = mnl_attr_get_u32(attr);
            __pr_nl(" <MTU> %u", mtu);
            break;
        case IFLA_OPERSTATE:
            operstate = mnl_attr_get_u8(attr);
            __pr_nl(" <OPERSTATE> %u", operstate);
            break;
        case IFLA_LINKMODE:
            linkmode = mnl_attr_get_u8(attr);
            __pr_nl(" <LINKMODE> %u", linkmode);
            break;
        case IFLA_LINK:
            link = mnl_attr_get_u32(attr);
            __pr_nl(" <LINK> %u", link);
            break;
        case IFLA_STATS:
            // Assume statistics as a payload (like struct rtnl_link_stats)
            stats = mnl_attr_get_payload(attr);
            __pr_nl(" <STATS> RX packets: %u, TX packets: %u",
                    stats->rx_packets, stats->tx_packets);
            break;
        case IFLA_QDISC:
            qdisc = mnl_attr_get_str(attr);
            __pr_nl(" <QDISC> %s", qdisc);
            break;
        case IFLA_CARRIER:
            carrier = mnl_attr_get_u8(attr);
            __pr_nl(" <CARRIER> %u", carrier);
            break;
        case IFLA_MASTER:
            master = mnl_attr_get_u32(attr);
            __pr_nl(" <MASTER> %u", master);
            break;
        case IFLA_NUM_TX_QUEUES:
            num_tx_queues = mnl_attr_get_u32(attr);
            __pr_nl(" <NUM_TX_QUEUES> %u", num_tx_queues);
            break;
        case IFLA_NUM_RX_QUEUES:
            num_rx_queues = mnl_attr_get_u32(attr);
            __pr_nl(" <NUM_RX_QUEUES> %u", num_rx_queues);
            break;
        case IFLA_LINKINFO:
            __pr_nl(" <LINKINFO> NESTED");

            // Parse the nested attributes
            mnl_attr_for_each_nested(nested_attr, attr) {
                nested_type = mnl_attr_get_type(nested_attr);

                __pr_nl("\n> [NESTED ATTR %d] %d octets", nested_type,
                        mnl_attr_get_len(nested_attr));

                switch (nested_type) {
                    case IFLA_INFO_KIND: {
                        kind = mnl_attr_get_str(nested_attr);
                        __pr_nl(" <INFO_KIND> %s", kind);
                        break;
                    }
                    case IFLA_INFO_DATA: {
                        __pr_nl(" <INFO_DATA> NESTED");
                        struct nlattr *info_data_attr;
                        mnl_attr_for_each_nested(info_data_attr, nested_attr) {
                            int info_data_type = mnl_attr_get_type(
                                info_data_attr);
                            __pr_nl("\n>   [INFO_DATA ATTR %d] %d octets",
                                    info_data_type, mnl_attr_get_len(
                                        info_data_attr));
                        }
                        break;
                    }
                    default:
                        __pr_nl(" <UNKNOWN NESTED(%d)>", nested_type);
                        break;
                }
            }
        case IFLA_GSO_MAX_SEGS:
            gso_max_segs = mnl_attr_get_u32(attr);
            __pr_nl(" <GSO_MAX_SEGS> %u", gso_max_segs);
            break;
        case IFLA_GSO_MAX_SIZE:
            gso_max_size = mnl_attr_get_u32(attr);
            __pr_nl(" <GSO_MAX_SIZE> %u", gso_max_size);
            break;
        default:
            // Print unknown attributes
            __pr_nl(" <UNKNOWN(%d)>", type);
            break;
    }
    __pr_nl("\n");

    return MNL_CB_OK;
}

int pr_nl_link(const struct nlmsghdr *nlh)
{
    struct ifinfomsg *ifm = mnl_nlmsg_get_payload(nlh);

    __pr_nl(">  [LINK Header] %d octets\n", nlh->nlmsg_len);
    __pr_nl(">    .ifi_family = %d\n", ifm->ifi_family);
    __pr_nl(">    .ifi_type = %d\n", ifm->ifi_type);
    __pr_nl(">    .ifi_index = %d\n", ifm->ifi_index);
    __pr_nl(">    .ifi_flags = %d <", ifm->ifi_flags);
    unsigned flags = ifm->ifi_flags;
    while (flags) {
        int bit_pos = __builtin_ctzll(flags);
        int flag = 1 << bit_pos;
        if (flag & IFF_UP)
            __pr_nl("UP");
        if (flag & IFF_BROADCAST)
            __pr_nl("BROADCAST");
        if (flag & IFF_DEBUG)
            __pr_nl("DEBUG");
        if (flag & IFF_LOOPBACK)
            __pr_nl("LOOPBACK");
        if (flag & IFF_POINTOPOINT)
            __pr_nl("POINTOPOINT");
        if (flag & IFF_NOTRAILERS)
            __pr_nl("NOTRAILERS");
        if (flag & IFF_RUNNING)
            __pr_nl("RUNNING");
        if (flag & IFF_NOARP)
            __pr_nl("NOARP");
        if (flag & IFF_PROMISC)
            __pr_nl("PROMISC");
        if (flag & IFF_ALLMULTI)
            __pr_nl("ALLMULTI");
        if (flag & IFF_MASTER)
            __pr_nl("MASTER");
        if (flag & IFF_SLAVE)
            __pr_nl("SLAVE");
        if (flag & IFF_MULTICAST)
            __pr_nl("MULTICAST");
        if (flag & IFF_PORTSEL)
            __pr_nl("PORTSEL");
        if (flag & IFF_AUTOMEDIA)
            __pr_nl("AUTOMEDIA");
        if (flag & IFF_DYNAMIC)
            __pr_nl("DYNAMIC");
        if (flag > IFF_DYNAMIC)
            __pr_nl("UNKNOWN(0x%x)", flag);
        if (__builtin_popcountll(flags) > 1)
            __pr_nl(",");
        flags &= (flags - 1);
    }
    __pr_nl(">\n");
    __pr_nl(">    .ifi_change = %d\n", ifm->ifi_change);

    mnl_attr_parse(nlh, sizeof(*ifm), pr_nl_attr_link, NULL);

    return MNL_CB_OK;
}

int pr_nl_attr_neigh(const struct nlattr *attr, void *data)
{
    int type = mnl_attr_get_type(attr);
    struct ndmsg *ndm = (struct ndmsg *)data;
    __u8 mac_str[MAC_ADDR_STR_LEN];
    char ip_str[INET6_ADDRSTRLEN];

    __pr_nl(">  [ATTR %d] %d octets", mnl_attr_get_type(attr),
             mnl_attr_get_len(attr));
    switch (type) {
        case NDA_UNSPEC:
            __pr_nl(" <UNSPEC>");
            break;
        case NDA_DST:
            const unsigned char *addr = mnl_attr_get_payload(attr);
            if (ndm->ndm_family == AF_INET)
                inet_ntop(AF_INET, addr, ip_str, INET_ADDRSTRLEN);
            else if (ndm->ndm_family == AF_INET6)
                format_ip_address(ip_str, sizeof(ip_str), (struct in6_addr *)addr);
            __pr_nl(" <DST> IP: %s", ip_str);
            break;
        case NDA_LLADDR:
            if (mnl_attr_get_len(attr) >= ETH_ALEN) {
                mac_to_string(mac_str, mnl_attr_get_payload(attr), sizeof(mac_str));
                __pr_nl(" <LLADDR> MAC: %s", mac_str);
            } else {
                __pr_nl(" <LLADDR>");
            }
            break;
        case NDA_CACHEINFO:
            __pr_nl(" <CACHEINFO>");
            break;
        case NDA_PROBES:
            __pr_nl(" <PROBES>");
            break;
        case NDA_VLAN:
            __pr_nl(" <VLAN> LAN ID: %d", mnl_attr_get_u16(attr));
            break;
        case NDA_PORT:
            __pr_nl(" <PORT> PORT: %d", mnl_attr_get_u16(attr));
            break;
        case NDA_VNI:
            __pr_nl(" <VNI> VNI: %d", mnl_attr_get_u32(attr));
            break;
        case NDA_IFINDEX:
            __pr_nl(" <IFINDEX> IFINDEX: %d", mnl_attr_get_u32(attr));
            break;
        case NDA_MASTER:
            __pr_nl(" <MASTER>");
            break;
        case NDA_LINK_NETNSID:
            __pr_nl(" <LINK_NETNSID>");
            break;
        case NDA_SRC_VNI:
            __pr_nl(" <SRC_VNI> SRC_VNI: %d", mnl_attr_get_u32(attr));
            break;
        case NDA_PROTOCOL:
            __pr_nl(" <PROTOCOL> PROTOCOL: %d", mnl_attr_get_u32(attr));
            break;
        case NDA_NH_ID:
            __pr_nl(" <NH_ID>");
            break;
        case NDA_FDB_EXT_ATTRS:
            __pr_nl(" <FDB_EXT_ATTRS>");
            break;
        case NDA_FLAGS_EXT:
            __pr_nl(" <FLAGS_EXT>");
            break;
        case NDA_NDM_STATE_MASK:
            __pr_nl(" <NDM_STATE_MASK>");
            break;
        case NDA_NDM_FLAGS_MASK:
            __pr_nl(" <NDM_FLAGS_MASK>");
            break;
        default:
            __pr_nl(" <UNKNOWN(%d)>", type);
            break;
    }
    __pr_nl("\n");

    return MNL_CB_OK;
}

int pr_nl_neigh(const struct nlmsghdr *nlh)
{
    struct ndmsg *ndm = mnl_nlmsg_get_payload(nlh);

    __pr_nl(">  [NEIGHBOR Header] %d octets\n", nlh->nlmsg_len);
    __pr_nl(">    .ndm_family = %d\n", ndm->ndm_family);
    __pr_nl(">    .ndm_ifindex = %d\n", ndm->ndm_ifindex);
    __pr_nl(">    .ndm_state = <");
    unsigned states = ndm->ndm_state;
    while (states) {
        int bit_pos = __builtin_ctzll(states);
        int state = 1 << bit_pos;
        if (state & NUD_INCOMPLETE)
            __pr_nl("INCOMPLETE");
        if (state & NUD_REACHABLE)
            __pr_nl("REACHABLE");
        if (state & NUD_STALE)
            __pr_nl("STALE");
        if (state & NUD_DELAY)
            __pr_nl("DELAY");
        if (state & NUD_PROBE)
            __pr_nl("PROBE");
        if (state & NUD_FAILED)
            __pr_nl("FAILED");
        if (state & NUD_NOARP)
            __pr_nl("NOARP");
        if (state & NUD_PERMANENT)
            __pr_nl("PERMANENT");
        if (state > NUD_PERMANENT)
            __pr_nl("UNKNOWN(0x%x)", state);
        if (__builtin_popcountll(states) > 1)
            __pr_nl(",");
        states &= (states - 1);
    }
    __pr_nl(">\n");
    __pr_nl(">    .ndm_flags = %d <", ndm->ndm_flags);
    unsigned flags = ndm->ndm_flags;
    while (flags) {
        int bit_pos = __builtin_ctzll(flags);
        int flag = 1 << bit_pos;
        if (flag & NTF_USE)
                __pr_nl("USE");
        if (flag & NTF_SELF)
            __pr_nl("SELF");
        if (flag & NTF_MASTER)
            __pr_nl("MASTER");
        if (flag & NTF_PROXY)
            __pr_nl("PROXY");
        if (flag & NTF_EXT_LEARNED)
            __pr_nl("EXT_LEARNED");
        if (flag & NTF_OFFLOADED)
            __pr_nl("OFFLOADED");
        if (flag & NTF_STICKY)
            __pr_nl("STICKY");
        if (flag & NTF_ROUTER)
            __pr_nl("ROUTER");
        if (flag > NTF_ROUTER)
            __pr_nl("UNKNOWN(0x%x)", flag);

        if (__builtin_popcountll(flags) > 1)
            __pr_nl(",");
        flags &= (flags - 1);
    }
    __pr_nl(">\n");
    __pr_nl(">    .ndm_type = %d\n", ndm->ndm_type);

    mnl_attr_parse(nlh, sizeof(*ndm), pr_nl_attr_neigh, ndm);

    return MNL_CB_OK;
}

int pr_nl_attr(const struct nlattr *attr, void *data)
{
    pr_nl(">  [ATTR %d] %d octets", mnl_attr_get_type(attr),
             mnl_attr_get_len(attr));
    for (int i = 0; i < mnl_attr_get_len(attr); i++) {
        if (i % 16 == 0)
            __pr_nl("  ");
        __pr_nl("%02x ", ((unsigned char *)mnl_attr_get_payload(attr))[i]);
        if (i % 16 == 15)
            __pr_nl("\n>");
    }
    __pr_nl("\n");
    return MNL_CB_OK;
}

int pr_nl_ndm(const struct nlmsghdr *nlh)
{
    struct ndmsg *ndm = mnl_nlmsg_get_payload(nlh);

    if (nlh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = mnl_nlmsg_get_payload(nlh);
        __pr_nl(">  [ERROR] ", err->error);
        __pr_nl(">    .error = %d\n", err->error);
        __pr_nl(">    .msg = %s\n", strerror(-err->error));
        return MNL_CB_OK;
    }
    __pr_nl(">  [PAYLOAD] %d octets\n", nlh->nlmsg_len);
    __pr_nl(">");
    for (int i = 0; i < nlh->nlmsg_len; i++) {
        if (i % 16 == 0)
            __pr_nl("  ");
        __pr_nl("%02x ", ((unsigned char *)nlh)[i]);
        if (i % 16 == 15)
            __pr_nl("\n>");
    }
    __pr_nl("\n");

    mnl_attr_parse(nlh, sizeof(*ndm), pr_nl_attr, NULL);

    return MNL_CB_OK;
}

static int __pr_nl_nlmsg_cb(const struct nlmsghdr *nlh, void *data)
{
    int ret;

    __pr_nl(">----------- BEGIN NETLINK MESSAGE -----------\n");
    __pr_nl(">  [NETLINK Header ] %d octets\n", nlh->nlmsg_len);

    __pr_nl(">    .nlmsg_len = %d\n", nlh->nlmsg_len);
    __pr_nl(">    .type = %d <", nlh->nlmsg_type, nlh->nlmsg_type);
    switch (nlh->nlmsg_type) {
        case NLMSG_NOOP:
            __pr_nl("NOOP");
            break;
        case NLMSG_ERROR:
            __pr_nl("ERROR");
            break;
        case NLMSG_DONE:
            __pr_nl("DONE");
            break;
        case NLMSG_OVERRUN:
            __pr_nl("OVERRUN");
            break;
        case RTM_GETLINK:
            __pr_nl("GETLINK");
            break;
        case RTM_NEWLINK:
            __pr_nl("NEWLINK");
            break;
        case RTM_NEWNEIGH:
            __pr_nl("NEWNEIGH");
            break;
        case RTM_GETNEIGH:
            __pr_nl("GETNEIGH");
            break;
        default:
            __pr_nl("UNKNOWN(%d)", nlh->nlmsg_type);
            break;
    }
    __pr_nl(">\n");
    __pr_nl(">    .flags = %d <", nlh->nlmsg_flags, nlh->nlmsg_flags);
    unsigned flags = nlh->nlmsg_flags;
    while (flags) {
        int bit_pos = __builtin_ctzll(flags);
        int flag = 1 << bit_pos;
        if (flag & NLM_F_REQUEST)
            __pr_nl("REQUEST");
        if (flag & NLM_F_MULTI)
            __pr_nl("MULTI");
        if (flag & NLM_F_ACK)
            __pr_nl("ACK");
        if (flag & NLM_F_ECHO)
            __pr_nl("ECHO");
        if (flag & NLM_F_DUMP_INTR)
            __pr_nl("DUMP_INTR");
        if (flag & NLM_F_DUMP_FILTERED)
            __pr_nl("DUMP_FILTERED");
        if (nlh->nlmsg_type == RTM_NEWNEIGH ||
            nlh->nlmsg_type == RTM_NEWLINK ||
            nlh->nlmsg_type == RTM_NEWADDR) {
            if (flag & NLM_F_ROOT)
                __pr_nl("ROOT");
            if (flag & NLM_F_MATCH)
                __pr_nl("MATCH");
            if (flag & NLM_F_ATOMIC)
                __pr_nl("ATOMIC");
        } else if (nlh->nlmsg_type == RTM_GETNEIGH ||
                   nlh->nlmsg_type == RTM_GETLINK ||
                   nlh->nlmsg_type == RTM_GETADDR) {
            if (flag & NLM_F_REPLACE)
                __pr_nl("REPLACE");
            if (flag & NLM_F_EXCL)
                __pr_nl("EXCL");
            if (flag & NLM_F_CREATE)
                __pr_nl("CREATE");
            if (flag & NLM_F_APPEND)
                __pr_nl("APPEND");
        } else if (nlh->nlmsg_type == RTM_DELNEIGH ||
                   nlh->nlmsg_type == RTM_DELLINK ||
                   nlh->nlmsg_type == RTM_DELADDR) {
            if (flag & NLM_F_NONREC)
                __pr_nl("NONREC");
            if (flag & NLM_F_BULK)
                __pr_nl("BULK");
        } else if (flag >= NLM_F_DUMP_FILTERED)
            __pr_nl("UNKNOWN(0x%x)", flag);
        if (__builtin_popcountll(flags) > 1)
            __pr_nl(",");
        flags &= (flags - 1);
    }
    __pr_nl(">\n");
    __pr_nl(">    .seq = %d\n", nlh->nlmsg_seq);
    __pr_nl(">    .port = %d\n", nlh->nlmsg_pid);

    if (nlh->nlmsg_type == RTM_NEWLINK || nlh->nlmsg_type == RTM_GETLINK)
        ret = pr_nl_link(nlh);
    else if (nlh->nlmsg_type == RTM_NEWNEIGH || nlh->nlmsg_type == RTM_GETNEIGH)
        ret = pr_nl_neigh(nlh);
    else
        ret = pr_nl_ndm(nlh);
    if (ret <= MNL_CB_ERROR) {
        pr_nl(">>>error parsing netlink message<<<\n");
        return MNL_CB_ERROR;
    }
    __pr_nl(">-----------  END NETLINK MESSAGE  -----------\n");
    return MNL_CB_OK;
}

void pr_nl_nlmsg(struct nlmsghdr *nlh, size_t num_bytes)
{
    if (!env.netlink)
        return;

    mnl_cb_run(nlh, num_bytes, nlh->nlmsg_seq, nl_env.mnl_portid,
                     __pr_nl_nlmsg_cb, NULL);
}
