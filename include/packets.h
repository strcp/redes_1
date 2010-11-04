#include <netinet/ip6.h>
#include <netinet/icmp6.h>

unsigned short icmp6_cksum(struct ip6_hdr *ip6);
char *alloc_pkt2big();
