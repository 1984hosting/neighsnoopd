/* SPDX-License-Identifier: GPL-2.0-or-later */
/* SPDX-FileCopyrightText: 2024 - 1984 Hosting Company <1984@1984.is> */
/* SPDX-FileCopyrightText: 2024 - Freyx Solutions <frey@freyx.com> */
/* SPDX-FileContributor: Freysteinn Alfredsson <freysteinn@freysteinn.com> */
/* SPDX-FileContributor: Julius Thor Bess Rikardsson <juliusbess@gmail.com> */

#ifndef NEIGHSNOOPD_SHARED_H_
#define NEIGHSNOOPD_SHARED_H_

struct network_entry {
    __u32 prefixlen;
    struct in6_addr network;
};

struct network_value {
    __u32 network_id;
};

struct neighbor_reply {
    __u8 mac[6];
    __be32 vlan_id;
    __u32 network_id;

    struct in6_addr ip;
    __u8 in_family;
    __u32 ingress_ifindex;
};

/*
 * Maps an IPv4 address into an IPv6 address according to RFC 4291 sec 2.5.5.2
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
static void map_ipv4_to_ipv6(struct in6_addr *ipv6, __be32 ipv4)
{
    __builtin_memset(((__u8 *)ipv6), 0x00, 10);
    __builtin_memset(((__u8 *)ipv6) + 10, 0xff, 2);
    ((__u32 *)ipv6)[3] = ipv4;
}
#pragma GCC diagnostic pop

#endif // NEIGHSNOOPD_SHARED_H_
