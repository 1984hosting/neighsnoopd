/* SPDX-License-Identifier: GPL-2.0-or-later */
/* SPDX-FileCopyrightText: 2024 - 1984 <1984@1984.is> */
/* SPDX-FileCopyrightText: 2024 - Freyx Solutions <frey@freyx.com> */
/* SPDX-FileContributor: Freysteinn Alfredsson <freysteinn@freysteinn.com> */
/* SPDX-FileContributor: Julius Thor Bess Rikardsson <juliusbess@gmail.com> */

#include <string.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>

#include "neighsnoopd.h"

extern struct env env;

void mac_to_string(__u8 *buffer, const __u8 *mac, size_t buffer_size)
{
    if (buffer_size < MAC_ADDR_STR_LEN) { // "XX:XX:XX:XX:XX:XX" + null terminator
        buffer[0] = '\0'; // Not enough space, return an empty string
        return;
    }
    snprintf((char *)buffer, buffer_size, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

bool is_zero_mac(const __u8 *mac)
{
    return mac[0] == 0 && mac[1] == 0 && mac[2] == 0 &&
           mac[3] == 0 && mac[4] == 0 && mac[5] == 0;
}

bool is_same_mac(const __u8 *mac1, const __u8 *mac2)
{
    return mac1[0] == mac2[0] && mac1[1] == mac2[1] && mac1[2] == mac2[2] &&
           mac1[3] == mac2[3] && mac1[4] == mac2[4] && mac1[5] == mac2[5];
}

void calculate_network_address(const struct in6_addr *ip,
                               const struct in6_addr *netmask,
                               struct in6_addr *network)
{
    for (int i = 0; i < 16; i++)
        network->s6_addr[i] = ip->s6_addr[i] & netmask->s6_addr[i];
}

struct in6_addr calculate_network_using_cidr(const struct in6_addr *ip,
                                               int cidr)
{
    struct in6_addr network = *ip;

    // Treat the IPv6 address as two 64-bit chunks
    uint32_t *addr_part = (uint32_t*)&network.s6_addr[0];

    for (int i = 0; i < 4; i++) {
        if (cidr >= 32) {
            // If the CIDR prefix is >= 32, no modification needed
            cidr -= 32;
        } else if (cidr > 0) {
            // Mask out the bits when its less than 32 bit
            uint32_t mask = ~((1 << (32 - cidr)) - 1);
            addr_part[i] = addr_part[i] & htonl(mask);
            cidr = 0;
        } else {
            // Zero out the rest of the address
            addr_part[i] = 0;
        }
    }
    return network;
}

int compare_ipv6_addresses(const struct in6_addr *addr1,
                           const struct in6_addr *addr2)
{
    return memcmp(addr1, addr2, sizeof(struct in6_addr)) == 0;
}

/*
 * Handle printing IPv4 addresses without the ::ffff: prefix
 */
int format_ip_address(char *buf, size_t size, const struct in6_addr *addr)
{
    if (IN6_IS_ADDR_V4MAPPED(addr))
        return inet_ntop(AF_INET, &addr->s6_addr[12], buf, size) == 0;
    else
        return inet_ntop(AF_INET6, addr, buf, size) == 0;
}

int format_ip_address_cidr(char *buf, size_t size, const struct in6_addr *addr,
                        int cidr)
{
    const char *ret;
    if (IN6_IS_ADDR_V4MAPPED(addr)) {
        ret = inet_ntop(AF_INET, &addr->s6_addr[12], buf, size);
        if (!ret)
            return -1;
        return snprintf(buf + strlen(buf), size - strlen(buf), "/%d", cidr - 96);
    } else {
        ret = inet_ntop(AF_INET6, addr, buf, size);
        if (!ret)
            return -1;
        return snprintf(buf + strlen(buf), size - strlen(buf), "/%d", cidr);
    }
}

/*
 * Function to calculate the CIDR of an IPv6 address
 */
int calculate_cidr(const struct in6_addr *addr)
{
    int cidr = 0;

    // Check if the address is an IPv4-mapped IPv6 address
    if (IN6_IS_ADDR_V4MAPPED(addr)) {
        // Extract the IPv4 part (last 4 bytes)
        struct in_addr ipv4_addr;
        memcpy(&ipv4_addr, &addr->s6_addr[12], sizeof(ipv4_addr));

        cidr = __builtin_popcount(ntohl(ipv4_addr.s_addr));
    } else {
        // Count the number of set bits in the IPv6 address
        for (int i = 0; i < 4; i++)
            cidr += __builtin_popcountl(addr->__in6_u.__u6_addr32[i]);
    }
    return cidr;
}

struct timespec get_time(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts;
}
