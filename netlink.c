/* SPDX-License-Identifier: GPL-2.0-or-later */
/* SPDX-FileCopyrightText: 2024 - 1984 Hosting Company <1984@1984.is> */
/* SPDX-FileCopyrightText: 2024 - Freyx Solutions <frey@freyx.com> */
/* SPDX-FileContributor: Freysteinn Alfredsson <freysteinn@freysteinn.com> */
/* SPDX-FileContributor: Julius Thor Bess Rikardsson <juliusbess@gmail.com> */

#include "neighsnoopd.h"

#include <errno.h>
#include <stdlib.h>
#include <libmnl/libmnl.h>
#include <linux/rtnetlink.h>
#include <glib.h>
#include <arpa/inet.h>

extern struct env env;

// Netlink environment
struct nl_env nl_env = {
    .netlink_tx_in_progress = false,
    .netlink_tx_queue = NULL,
    .netlink_tx_queue_count = 0,
    .netlink_tx_count = 0,

    .netlink_cmd_queue = NULL,
    .netlink_cmd_count = 0,
};

int netlink_process_rx_queue(void)
{
    int ret;
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;

    ret = mnl_socket_recvfrom(nl_env.nl, buf, sizeof(buf));
    if (ret < 0) {
        pr_err(errno, "mnl_socket_recvfrom");
        return errno;
    }

    nlh = (struct nlmsghdr *)buf;

    pr_nl("Received Netlink message: >>>>\n");
    pr_nl_nlmsg(nlh, ret);
    pr_nl("End of Received Netlink message: <<<<\n");

    ret = mnl_cb_run(nlh, ret, nlh->nlmsg_seq, nl_env.mnl_portid,
                     netlink_handle_all_cb, NULL);
    if (ret < 0) {
        pr_err(errno, "Failed to parse Netlink message");
        return errno;
    }

    // Handle finished TX messages
    if (nlh->nlmsg_type == NLMSG_DONE)
        netlink_queue_check_ack_tx_queue(nlh);

    if (nlh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);

        if (err->error != 0)
            pr_err(err->error, "Netlink error");

        netlink_queue_check_ack_tx_queue(&err->msg);
    }

    if (!env.has_links && env.link_seq == nlh->nlmsg_seq)
        env.has_links = true;
    if (!env.has_networks && env.addr_seq == nlh->nlmsg_seq)
        env.has_networks = true;
    if (!env.has_fdb && env.fdb_seq == nlh->nlmsg_seq)
        env.has_fdb = true;

    return 0;
}

bool netlink_queue_cmd(union netlink_cmd *cmd)
{
    union netlink_cmd *cmd_copy = calloc(1, sizeof(*cmd));
    // Copy the right size of the command. This prevents flagging
    // by memory sanitizers
    switch (cmd->cmd_type) {
        case CMD_FDB_ADD:
        case CMD_FDB_DEL:
            memcpy(&cmd_copy->neigh, &cmd->neigh, sizeof(cmd->neigh));
            break;
        case CMD_NEIGH_ADD:
        case CMD_NEIGH_DEL:
            memcpy(&cmd_copy->neigh, &cmd->neigh, sizeof(cmd->neigh));
            break;
        case CMD_ADDR_ADD:
        case CMD_ADDR_DEL:
            memcpy(&cmd_copy->addr, &cmd->addr, sizeof(cmd->addr));
            break;
        case CMD_LINK_ADD:
        case CMD_LINK_DEL:
            memcpy(&cmd_copy->link, &cmd->link, sizeof(cmd->link));
            break;
        case CMD_NONE:
            break;
    }

    nl_env.netlink_cmd_queue = g_list_append(nl_env.netlink_cmd_queue, cmd_copy);
    if (!nl_env.netlink_cmd_queue) {
        pr_err(errno, "Failed to add Netlink command to queue");
        return false;
    }

    return true;
}

union netlink_cmd *netlink_dequeue_cmd(void)
{
    union netlink_cmd *cmd;
    if (nl_env.netlink_cmd_queue == NULL)
        return NULL;

    cmd = nl_env.netlink_cmd_queue->data;
    nl_env.netlink_cmd_queue = g_list_delete_link(nl_env.netlink_cmd_queue,
                                                  nl_env.netlink_cmd_queue);
    return cmd;
}

int netlink_parse_neigh_attr_cb(const struct nlattr *attr, void *data)
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
        case NDA_IFINDEX:
            if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
                pr_err(errno, "mnl_attr_validate");
                return MNL_CB_ERROR;
            }
            break;
    }

    tb[type] = attr;
    return MNL_CB_OK;
}

int netlink_handle_neigh_cb(const struct nlmsghdr *nlh, void *data)
{
    int type = nlh->nlmsg_type;
    struct ndmsg *ndm = mnl_nlmsg_get_payload(nlh);
    struct netlink_neigh_cmd neigh = {0};

    struct nlattr *tb[NDA_MAX + 1] = {};

    if (ndm->ndm_flags & NTF_ROUTER || ndm->ndm_flags & NTF_PROXY)
        return MNL_CB_OK;

    mnl_attr_parse(nlh, sizeof(struct ndmsg), netlink_parse_neigh_attr_cb, tb);

    neigh.type = type;

    if (tb[NDA_LLADDR]) {
        memcpy(&neigh.mac, mnl_attr_get_payload(tb[NDA_LLADDR]),
               sizeof(neigh.mac));
        if (is_zero_mac(neigh.mac))
            return MNL_CB_OK;
    }

    if (tb[NDA_DST]) {
        if (ndm->ndm_family == AF_INET) {
            struct in_addr ipv4_addr;
            memcpy(&ipv4_addr, mnl_attr_get_payload(tb[NDA_DST]),
                   sizeof(ipv4_addr));
            map_ipv4_to_ipv6(&neigh.ip, ipv4_addr.s_addr);
        } else {
            memcpy(&neigh.ip, mnl_attr_get_payload(tb[NDA_DST]),
                   sizeof(neigh.ip));
        }
        neigh.has_ip = true;
    }

    if (tb[NDA_IFINDEX])
        neigh.ifindex = mnl_attr_get_u32(tb[NDA_IFINDEX]);
    else
        neigh.ifindex = ndm->ndm_ifindex;

    if (ndm->ndm_flags & NTF_EXT_LEARNED)
        neigh.is_externally_learned = true;

    neigh.nud_state = ndm->ndm_state;

    // Queue the FDB or Neighbor command
    if (ndm->ndm_family == AF_BRIDGE) {
        if (type == RTM_NEWNEIGH)
            neigh.cmd_type = CMD_FDB_ADD;
        else if (type == RTM_DELNEIGH)
            neigh.cmd_type = CMD_FDB_DEL;
        netlink_queue_cmd((union netlink_cmd *) &neigh);
    } else if (ndm->ndm_family == AF_INET6 || ndm->ndm_family == AF_INET) {
        if (type == RTM_NEWNEIGH)
            neigh.cmd_type = CMD_NEIGH_ADD;
        else if (type == RTM_DELNEIGH)
            neigh.cmd_type = CMD_NEIGH_DEL;
        netlink_queue_cmd((union netlink_cmd *) &neigh);
    }

    return MNL_CB_OK;
}

int netlink_parse_addr_attr_cb(const struct nlattr *attr, void *data)
{
    const struct nlattr **tb = data;
    int type = mnl_attr_get_type(attr);

    if (mnl_attr_type_valid(attr, IFA_MAX) < 0)
        return MNL_CB_OK;

    switch(type) {
        case IFA_ADDRESS:
            if (mnl_attr_validate(attr, MNL_TYPE_BINARY) < 0) {
                pr_err(errno, "mnl_attr_validate");
                return MNL_CB_ERROR;
            }
            break;
    }

    tb[type] = attr;
    return MNL_CB_OK;
}

int netlink_handle_addr_cb(const struct nlmsghdr *nlh, void *data)
{
    int type = nlh->nlmsg_type;
    struct netlink_addr_cmd addr = {0};
    struct ifaddrmsg *ifa = mnl_nlmsg_get_payload(nlh);

    struct nlattr *tb[IFA_MAX + 1] = {};

    mnl_attr_parse(nlh, sizeof(*ifa), netlink_parse_addr_attr_cb, tb);

    if (tb[IFA_ADDRESS] == NULL)
        return MNL_CB_OK;

    addr.ifindex = ifa->ifa_index;
    addr.prefixlen = ifa->ifa_prefixlen;
    addr.true_prefixlen = ifa->ifa_prefixlen;
    addr.flags = ifa->ifa_flags;

    // IPv4 and IPv6 addresses are stored in the same field
    if (ifa->ifa_family == AF_INET) {
        struct in_addr ipv4_addr;
        memcpy(&ipv4_addr, mnl_attr_get_payload(tb[IFA_ADDRESS]),
               sizeof(ipv4_addr));
        map_ipv4_to_ipv6(&addr.ip, ipv4_addr.s_addr);
        addr.prefixlen += 96;
    } else {
        memcpy(&addr.ip, mnl_attr_get_payload(tb[IFA_ADDRESS]),
               sizeof(addr.ip));
    }

    addr.network = calculate_network_using_cidr(&addr.ip, addr.prefixlen);

    // Queue the address command
    if (type == RTM_NEWADDR)
        addr.cmd_type = CMD_ADDR_ADD;
    else if (type == RTM_DELADDR)
        addr.cmd_type = CMD_ADDR_DEL;
    netlink_queue_cmd((union netlink_cmd *) &addr);

    return MNL_CB_OK;
}

int netlink_parse_link_infodata_attr_cb(const struct nlattr *attr, void *data)
{
    int type = mnl_attr_get_type(attr);
    bool found = false;

    if (mnl_attr_type_valid(attr, IFLA_INFO_MAX) < 0)
        return MNL_CB_OK;

    switch (type) {
        case IFLA_VLAN_PROTOCOL:
            if (mnl_attr_validate(attr, MNL_TYPE_U16))
                found = true;
            if (mnl_attr_validate(attr, MNL_TYPE_U32))
                found = true;

            if (!found) {
                pr_err(errno, "mnl_attr_validate");
                return MNL_CB_ERROR;
            }
            break;
        case IFLA_VLAN_ID:
            if (mnl_attr_validate(attr, MNL_TYPE_U16))
                found = true;
            if (mnl_attr_validate(attr, MNL_TYPE_U32))
                found = true;

            if (!found) {
                pr_err(errno, "mnl_attr_validate");
                return MNL_CB_ERROR;
            }
            break;
    }

    return MNL_CB_OK;
}

int netlink_parse_link_info_attr_cb(const struct nlattr *attr, void *data)
{
    int type = mnl_attr_get_type(attr);
    struct nlattr *nested_attr = NULL;

    if (mnl_attr_type_valid(attr, IFLA_INFO_MAX) < 0)
        return MNL_CB_OK;

    switch(type) {
        case IFLA_INFO_KIND:
            if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
                pr_err(errno, "mnl_attr_validate");
                return MNL_CB_ERROR;
            }
            break;
        case IFLA_INFO_SLAVE_KIND:
            if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
                pr_err(errno, "mnl_attr_validate");
                return MNL_CB_ERROR;
            }
        case IFLA_INFO_DATA:
            if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
                pr_err(errno, "mnl_attr_validate");
                return MNL_CB_ERROR;
            }
            mnl_attr_for_each_nested(nested_attr, attr) {
                if (mnl_attr_validate(attr, MNL_TYPE_UNSPEC) < 0) {
                    pr_err(errno, "mnl_attr_validate");
                    return MNL_CB_ERROR;
                }
                if (netlink_parse_link_infodata_attr_cb(nested_attr, data) < 0)
                    return MNL_CB_ERROR;
            }
    }

    return MNL_CB_OK;
}

int netlink_parse_link_attr_cb(const struct nlattr *attr, void *data)
{
    const struct nlattr **tb = data;
    int type = mnl_attr_get_type(attr);
    struct nlattr *nested_attr = NULL;

    /* skip unsupported attribute in user-space */
    if (mnl_attr_type_valid(attr, IFLA_MAX) < 0)
        return MNL_CB_OK;

    switch(type) {
        case IFLA_IFNAME:
            if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
                pr_err(errno, "mnl_attr_validate");
                return MNL_CB_ERROR;
            }
            break;
        case IFLA_LINK:
            if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
                pr_err(errno, "mnl_attr_validate");
                return MNL_CB_ERROR;
            }
            break;
        case IFLA_ADDRESS:
            if (mnl_attr_validate(attr, MNL_TYPE_BINARY) < 0) {
                pr_err(errno, "mnl_attr_validate");
                return MNL_CB_ERROR;
            }
            break;
        case IFLA_LINKINFO:
            if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
                pr_err(errno, "mnl_attr_validate");
                return MNL_CB_ERROR;
            }
            mnl_attr_for_each_nested(nested_attr, attr) {
                if (netlink_parse_link_info_attr_cb(nested_attr, data) < 0)
                    return MNL_CB_ERROR;
            }
    }
    tb[type] = attr;
    return MNL_CB_OK;
}

void netlink_handle_link_linkinfo(struct nlattr *tb[IFLA_MAX + 1],
                                  struct netlink_link_cmd *link)
{
    struct nlattr *link_attr;
    struct nlattr *nested_attr = NULL;

    if (!tb[IFLA_LINKINFO])
        return;

    mnl_attr_for_each_nested(link_attr, tb[IFLA_LINKINFO]) {
        if (mnl_attr_get_type(link_attr) == IFLA_INFO_KIND)
            snprintf(link->kind, sizeof(link->kind), "%s",
                     mnl_attr_get_str(link_attr));
        else if (mnl_attr_get_type(link_attr) == IFLA_INFO_SLAVE_KIND)
            snprintf(link->slave_kind, sizeof(link->slave_kind), "%s",
                     mnl_attr_get_str(link_attr));
        else if (mnl_attr_get_type(link_attr) == IFLA_INFO_DATA) {
            mnl_attr_for_each_nested(nested_attr, link_attr) {
                int nested_type = mnl_attr_get_type(nested_attr);

                if (nested_type == IFLA_VLAN_PROTOCOL) {
                    if (mnl_attr_validate(nested_attr, MNL_TYPE_U32))
                        link->vlan_protocol = mnl_attr_get_u32(nested_attr);
                    else
                        link->vlan_protocol = mnl_attr_get_u16(nested_attr);
                } else if (nested_type == IFLA_VLAN_ID) {
                    if (mnl_attr_validate(nested_attr, MNL_TYPE_U32))
                        link->vlan_id = mnl_attr_get_u32(nested_attr);
                    else
                        link->vlan_id = mnl_attr_get_u16(nested_attr);
                }
            }
        }
    }
}

int netlink_handle_link_cb(const struct nlmsghdr *nlh, void *data)
{
    int type = nlh->nlmsg_type;
    int err;
    struct netlink_link_cmd link = {0};
    struct ifinfomsg *ifm = mnl_nlmsg_get_payload(nlh);

    struct nlattr *tb[IFLA_MAX + 1] = {};

    // Parse the Link message
    err = mnl_attr_parse(nlh, sizeof(*ifm), netlink_parse_link_attr_cb, tb);
    if (err < 0)
        return MNL_CB_OK;

    if (!tb[IFLA_IFNAME])
        return MNL_CB_OK;

    if (!tb[IFLA_ADDRESS])
        return MNL_CB_OK;

    snprintf(link.ifname, sizeof(link.ifname), "%s",
             mnl_attr_get_str(tb[IFLA_IFNAME]));

    memcpy(&link.mac, mnl_attr_get_payload(tb[IFLA_ADDRESS]), sizeof(link.mac));

    link.ifindex = ifm->ifi_index;
    if (tb[IFLA_LINK])
        link.link_ifindex = mnl_attr_get_u32(tb[IFLA_LINK]);

    netlink_handle_link_linkinfo(tb, &link);

    if (strcmp(link.kind, "macvlan") == 0)
        link.is_macvlan = true;

    if (strcmp(link.slave_kind, "vrf") ==  0)
        link.is_vrf = true;

    if (link.vlan_protocol && link.vlan_id)
        link.has_vlan = true;

    // Queue the link command
    if (type == RTM_NEWLINK)
        link.cmd_type = CMD_LINK_ADD;
    else if (type == RTM_DELLINK)
        link.cmd_type = CMD_LINK_DEL;
    netlink_queue_cmd((union netlink_cmd *) &link);

    return MNL_CB_OK;
}

int netlink_handle_all_cb(const struct nlmsghdr *nlh, void *data)
{
    int ret;
    if (nlh->nlmsg_type == RTM_NEWLINK || nlh->nlmsg_type == RTM_DELLINK)
        ret = netlink_handle_link_cb(nlh, NULL);
    else if (nlh->nlmsg_type == RTM_NEWADDR || nlh->nlmsg_type == RTM_DELADDR)
        ret = netlink_handle_addr_cb(nlh, NULL);
    else if (nlh->nlmsg_type == RTM_NEWNEIGH || nlh->nlmsg_type == RTM_DELNEIGH)
        ret = netlink_handle_neigh_cb(nlh, NULL);
    else
        pr_debug("Received unknown Netlink message type %d\n",
                 nlh->nlmsg_type);

    nl_env.netlink_cmd_count++;

    return ret;
}

// Netlink setup and cleanup
int netlink_get_interfaces(void)
{
    int err = 0;
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    struct ifinfomsg *ifm;

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = RTM_GETLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;
    nlh->nlmsg_seq = ++nl_env.nlm_seq;
    if (!env.has_links)
        env.link_seq = nlh->nlmsg_seq;

    ifm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
    ifm->ifi_family = AF_UNSPEC;

    if (netlink_queue_add(nlh)) {
        pr_err(errno, "Failed to add Netlink message to tx queue");
        err = -1;
        goto out;
    }

out:
    return err;
}

int netlink_get_addresses(void)
{
    int err = 0;
    char buf[MNL_SOCKET_BUFFER_SIZE];

    struct nlmsghdr *nlh;
    struct ifaddrmsg *ifa;

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = RTM_GETADDR;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;
    nlh->nlmsg_seq = ++nl_env.nlm_seq;
    if (!env.has_networks)
        env.addr_seq = nlh->nlmsg_seq;

    ifa = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifaddrmsg));
    ifa->ifa_family = AF_UNSPEC;

    if (netlink_queue_add(nlh)) {
        pr_err(errno, "Failed to add Netlink message to tx queue");
        err = -1;
        goto out;
    }

out:
    return err;
}

int netlink_get_fdb(void)
{
    int err = 0;
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    struct ndmsg *ndm;

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = RTM_GETNEIGH;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;
    nlh->nlmsg_seq = ++nl_env.nlm_seq;
    if (!env.has_fdb)
        env.fdb_seq = nlh->nlmsg_seq;

    ndm = mnl_nlmsg_put_extra_header(nlh, sizeof(*ndm));
    ndm->ndm_family = AF_BRIDGE;
    ndm->ndm_ifindex = env.ifidx_mon;

    if (netlink_queue_add(nlh)) {
        pr_err(errno, "Failed to add Netlink message to tx queue");
        err = -1;
    }

    return err;
}

int netlink_get_neighs(int family)
{
    int err = 0;
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    struct ndmsg *ndm;

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = RTM_GETNEIGH;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;
    nlh->nlmsg_seq = ++nl_env.nlm_seq;

    ndm = mnl_nlmsg_put_extra_header(nlh, sizeof(*ndm));
    ndm->ndm_family = family;

    if (netlink_queue_add(nlh)) {
        pr_err(errno, "Failed to add Netlink message to tx queue");
        err = -1;
    }

    return err;
}

int netlink_send_neigh(struct neighbor_reply *reply, int ifindex)
{
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    struct ndmsg *ndm;
    struct in6_addr *addr = &reply->ip;
    int ret;

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = RTM_NEWNEIGH;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK;
    nlh->nlmsg_seq = ++nl_env.nlm_seq;

    ndm = mnl_nlmsg_put_extra_header(nlh, sizeof(*ndm));
    ndm->ndm_type = RTN_UNICAST;
    ndm->ndm_family = reply->in_family;
    ndm->ndm_state = NUD_REACHABLE;
    ndm->ndm_ifindex = ifindex;

    // Add IP address
    if (IN6_IS_ADDR_V4MAPPED(addr)) {
        struct in_addr ipv4_addr;
        memcpy(&ipv4_addr, &addr->s6_addr[12], sizeof(ipv4_addr));
        mnl_attr_put(nlh, NDA_DST, sizeof(ipv4_addr), &ipv4_addr);
    } else {
        mnl_attr_put(nlh, NDA_DST, sizeof(*addr), addr);
    }

    // Add MAC address
    mnl_attr_put(nlh, NDA_LLADDR, sizeof(reply->mac), reply->mac);

    ret = mnl_socket_sendto(nl_env.nl, nlh, nlh->nlmsg_len);
    if (ret < 0)
        pr_err(errno, "mnl_socket_sendto");

    return ret;
}

int netlink_queue_add(struct nlmsghdr *nlh)
{
    struct nlmsghdr *nlh_copy = malloc(nlh->nlmsg_len);
    if (!nlh_copy) {
        pr_err(errno, "malloc");
        return errno;
    }

    memcpy(nlh_copy, nlh, nlh->nlmsg_len);
    nl_env.netlink_tx_queue = g_list_append(nl_env.netlink_tx_queue, nlh_copy);

    nl_env.netlink_tx_queue_count++;

    return 0;
}

struct nlmsghdr *netlink_queue_peek(void)
{
    if (!nl_env.netlink_tx_queue)
        return NULL;

    return nl_env.netlink_tx_queue->data;
}

struct nlmsghdr *netlink_queue_pop(void)
{
    struct nlmsghdr *nlh = nl_env.netlink_tx_queue->data;
    nl_env.netlink_tx_queue = g_list_delete_link(nl_env.netlink_tx_queue,
                                                 nl_env.netlink_tx_queue);

    nl_env.netlink_tx_queue_count--;
    return nlh;
}

int netlink_queue_send(struct nlmsghdr *nlh)
{
    int ret;

    pr_nl_nlmsg(nlh, nlh->nlmsg_len);

    ret = mnl_socket_sendto(nl_env.nl, nlh, nlh->nlmsg_len);
    if (ret < 0) {
        pr_err(errno, "mnl_socket_sendto");
        return errno;
    }

    nl_env.netlink_tx_in_progress = true;
    nl_env.netlink_tx_count++;

    return 0;
}

int netlink_queue_send_next()
{
    struct nlmsghdr *nlh;
    int ret = 0;

    if (!nl_env.netlink_tx_queue)
        goto out;

    if (nl_env.netlink_tx_in_progress)
        goto out;

    nlh = netlink_queue_peek();
    ret = netlink_queue_send(nlh);

out:
    return ret;
}

void netlink_queue_check_ack_tx_queue(const struct nlmsghdr *nlh)
{
    struct nlmsghdr *head_of_queue;

    if (!nl_env.netlink_tx_in_progress)
        return;

    head_of_queue = netlink_queue_peek();
    if (head_of_queue) {
        if (nlh->nlmsg_seq != head_of_queue->nlmsg_seq)
            return;
    }

    netlink_queue_pop();
    pr_nl("Netlink message %d processed\n", nlh->nlmsg_seq);

    if (nlh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
        if (err->error != 0)
            pr_err(err->error, "Netlink error");
    }

    free(head_of_queue);
    nl_env.netlink_tx_in_progress = false;
}

void netlink_cmd_free(union netlink_cmd *cmd)
{
    free(cmd);
}

int setup_netlink(void)
{
    int err = 0;
    int size = 512 * 1024; // 512KB

    nl_env.nlm_seq = time(NULL);
    if (err) {
        fprintf(stderr, "Could not compile regex");
        goto out;
    }

    nl_env.nl = mnl_socket_open(NETLINK_ROUTE);
    if (nl_env.nl == NULL) {
        err = errno;
        perror("mnl_socket_open");
        goto out;
    }
    nl_env.mnl_portid = mnl_socket_get_portid(nl_env.nl);
    pr_nl("MNL port ID: %d\n", nl_env.mnl_portid);

    // Monitor for IPv4 and IPv6 network changes, link changes and
    // neighbor changes
    if (mnl_socket_bind(nl_env.nl, RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR |
                        RTMGRP_LINK | RTMGRP_NEIGH,
                        MNL_SOCKET_AUTOPID) < 0) {
        err = -errno;
        perror("mnl_socket_bind");
        goto out;
    }

    env.nl_fd = mnl_socket_get_fd(nl_env.nl);
    if (env.nl_fd < 0) {
        err = env.nl_fd;
        perror("mnl_socket_get_fd");
        goto out;
    }
    env.number_of_fds++;

    setsockopt(env.nl_fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

    err = netlink_get_interfaces();
    if (err) {
        perror("Failed to get interfaces");
        goto out;
    }

    err = netlink_get_addresses();
    if (err) {
        perror("Failed to get addresses");
        goto out;
    }

    err = netlink_get_fdb();
    if (err) {
        perror("Failed to get FDB entries");
        goto out;
    }

    err = netlink_get_neighs(AF_INET6);
    if (err) {
        perror("Failed to get IPv6 neighbors");
        goto out;
    }

    err = netlink_get_neighs(AF_INET);
    if (err) {
        perror("Failed to get IPv4 neighbors");
        goto out;
    }

out:
    return err;
}

void cleanup_netlink(void)
{
    if (nl_env.nl)
        mnl_socket_close(nl_env.nl);
}
