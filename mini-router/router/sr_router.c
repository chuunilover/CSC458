/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_utils2.h"


/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);
  printf("Interface: %s", interface);

  if (len < sizeof(struct sr_ethernet_hdr))
  {
    return; 
  }
  /* fill in code here */
  uint16_t ethType = ethertype(packet);

/* TODO: Add length checks */

  switch(ethType)
  {
    case ethertype_arp:
      printf("Processing ARP packet...");
      /* process ARP packet() */
      break;
    case ethertype_ip:
      printf("Processing IP packet...");
      sr_handleip(sr, packet, len, interface);
      /* process IP packet() */
      break;
    default: /* neither ARP nor IPV4 */
      printf("Discarding packet due to not being ARP or IPV4");
      return;
  }
}/* end sr_ForwardPacket */

/*
sr: The struct sr_instance
packet: The entire packet including ethernet header
len: Packet length (bytes) including headers
*/
void sr_handleip(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
{
    if (!sr || !packet)
        return;

    struct sr_ip_hdr *ip_header = get_ip_hdr(packet, len);
    if (!ip_header)
    {
        return;
    }

    

    uint8_t ip_proto = ip_header->ip_p;
    
    /* if for us */ 
    if (ip_header -> ip_dst == sr -> sr_addr.sin_addr.s_addr)
    {
        if (ip_proto == ip_protocol_icmp)
        {
            struct sr_icmp_hdr *icmp_header = get_icmp_hdr(packet, len);
            /* if length inappropriate */
            if (!icmp_header)
            {
                return;
            }
          
            /* if CKSUM failed */
            if (!check_icmp_sum(packet, len))
            {
                return;
            }
            
            /* if ICMP echo */
            if (icmp_header -> icmp_type == ICMP_ECHO_REQUEST)
            {
                sr_send_icmp_echo(sr, packet, len, interface);
                /* send echo reply */
            }
        }
        else if (ip_proto == IP_PROTOCOL_TCP || ip_proto == IP_PROTOCOL_UDP)
        {
            /* send destination unreachable*/
            sr_send_icmp_port_unreachable(sr, packet, len, interface);
        }
    }
    else
    {
        /* whoops nothing to do here` */
    }
}

void sr_handlearp(struct sr_instance *sr, uint8_t *packet, unsigned int len)
{
}

void sr_send_icmp_port_unreachable(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
{
    struct sr_icmp_hdr *icmp_header = get_icmp_hdr(packet, len);
    if (!icmp_header)
    {
        return;
    }
    icmp_header -> icmp_type = ICMP_TYPE_DEST_UNREACHABLE;
    icmp_header -> icmp_code = ICMP_CODE_PORT_UNREACHABLE;
    icmp_header -> icmp_sum = 0;
    icmp_header -> icmp_sum = cksum((void *)icmp_header, len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr));
    
    struct sr_ip_hdr *ip_header = get_ip_hdr(packet, len);
    if(!ip_header)
    {
        return;
    }

    ip_header -> ip_src ^= ip_header -> ip_dst;
    ip_header -> ip_dst ^= ip_header -> ip_src;
    ip_header -> ip_src ^= ip_header -> ip_dst; 
    
    ip_hdr -> ip_tos = 0;
    ip_hdr -> ip_id = 0;
    ip_hdr -> ip_off = 0;
    ip_hdr -> ip_ttl = 64;
    ip_hdr -> ip_p = IP_PROTOCOL_ICMP;
    
    set_proper_ip_cksum(packet, len);

    struct sr_ethernet_hdr *eth_hdr = get_ethernet_hdr(packet, len);
    if (!eth_hdr)
    {
        return;
    }

    uint8_t buf[ETHER_ADDR_LEN];
    memcpy((void *)buf, (void *)eth_hdr -> ether_dhost, ETHER_ADDR_LEN);
    memcpy((void *)eth_hdr -> ether_dhost, (void *)eth_hdr -> ether_shost, ETHER_ADDR_LEN);
    memcpy((void *)eth_hdr -> ether_shost, (void *)buf, ETHER_ADDR_LEN);

    sr_send_packet(sr, packet, len, interface);
}

void sr_send_icmp_echo(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
{
    struct sr_icmp_hdr *icmp_header = get_icmp_hdr(packet, len);
    if (!icmp_header)
    {
        return;
    }
    
    icmp_header->icmp_type = ICMP_TYPE_ECHO_REPLY;
    icmp_header->icmp_code = ICMP_CODE_ECHO_REPLY;
    icmp_header->icmp_sum = 0;
    icmp_header->icmp_sum = cksum((void *)icmp_header, len - sizeof(struct sr_ethernet_hdr) - sizeof (struct sr_ip_hdr));
    
    struct sr_ip_hdr *ip_hdr = get_ip_hdr(packet, len);
    if (!ip_hdr)
    {
        return;
    }

    /* 3 xor trick to swap ip_hdr -> ip_src and ip_hdr -> ip_dst */
    ip_hdr -> ip_src ^= ip_hdr -> ip_dst;
    ip_hdr -> ip_dst ^= ip_hdr -> ip_src;
    ip_hdr -> ip_src ^= ip_hdr -> ip_dst;

    ip_hdr -> ip_tos = 0;
    ip_hdr -> ip_id = 0;
    ip_hdr -> ip_off = 0;
    ip_hdr -> ip_ttl = 64;
    ip_hdr -> ip_p = IP_PROTOCOL_ICMP;
    
    set_proper_ip_cksum(packet, len);

    struct sr_ethernet_hdr *eth_hdr = get_ethernet_hdr(packet, len);
    if (!eth_hdr)
    {
        return;
    }

    uint8_t buf[ETHER_ADDR_LEN];
    memcpy((void *)buf, (void *)eth_hdr -> ether_dhost, ETHER_ADDR_LEN);
    memcpy((void *)eth_hdr -> ether_dhost, (void *)eth_hdr -> ether_shost, ETHER_ADDR_LEN);
    memcpy((void *)eth_hdr -> ether_shost, (void *)buf, ETHER_ADDR_LEN);

    sr_send_packet(sr, packet, len, interface);
}
