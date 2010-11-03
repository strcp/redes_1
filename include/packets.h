#include <netinet/ip6.h>
#include <netinet/icmp6.h>

unsigned short icmp6_crc(struct icmp6_hdr *hdr, struct ip6_hdr *dst);
char *alloc_pkt2big();
