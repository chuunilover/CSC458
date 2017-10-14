#include "sr_protocol.h"

#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_DEST_UNREACHABLE 3

#define ICMP_CODE_ECHO_REPLY 0
#define ICMP_CODE_PORT_UNREACHABLE 3

#define IP_PROTOCOL_ICMP 1

struct sr_ethernet_hdr *get_ethernet_hdr( uint8_t *, uint32_t );

struct sr_ip_hdr *get_ip_hdr( uint8_t *, uint32_t );

struct sr_icmp_hdr *get_icmp_hdr( uint8_t *, uint32_t );

int check_icmp_sum( uint8_t *, uint32_t );

void set_proper_ip_cksum( uint8_t *, uint32_t );

int check_ip_sum (uint8_t *, uint32_t );
