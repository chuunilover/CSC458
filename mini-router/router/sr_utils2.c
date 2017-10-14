#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sr_utils2.h"
#include "sr_protocol.h"
#include "sr_utils.h"

struct sr_ethernet_hdr *get_ethernet_hdr(uint8_t *packet, uint32_t len)
{
    if (len < sizeof(struct sr_ethernet_hdr))
    {
        return NULL;
    }
    return (struct sr_ethernet_hdr *)(packet);
}

struct sr_ip_hdr *get_ip_hdr(uint8_t *packet, uint32_t len)
{
    if (len < sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr))
    {
        return NULL;
    }
    return (struct sr_ip_hdr *)(packet + sizeof(struct sr_ethernet_hdr));
}

struct sr_icmp_hdr *get_icmp_hdr(uint8_t *packet, uint32_t len)
{
    if (len < sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_hdr))
    {
        return NULL;
    }
    return (struct sr_icmp_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
}

int check_icmp_sum(uint8_t *packet, uint32_t len)
{
    struct sr_icmp_hdr *hdr = get_icmp_hdr(packet, len);
    if (!hdr)
    {
        return 0;
    }
    
    return cksum((void *)hdr, len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr)) == 0;
}

void set_proper_ip_cksum(uint8_t *packet, uint32_t len)
{
    struct sr_ip_hdr *hdr = get_ip_hdr(packet, len);
    if (!hdr)
    {
        return;
    }

    hdr -> ip_sum = 0;
    hdr -> ip_sum = cksum((void *)hdr, sizeof(struct sr_ip_hdr));
}

int check_ip_cksum(uint8_t *packet, uint32_t len)
{
    struct sr_ip_hdr *hdr = get_ip_hdr(packet, len);
    
    if (!hdr)
    {
        return 0;
    }
    return cksum((void *)hdr, sizeof(struct sr_ip_hdr)) == 0;  
}
