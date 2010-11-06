#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <victims.h>

void debug_packet(char *packet);

char *alloc_pkt2big(struct victim *svic, struct victim *dvic);
char *alloc_ndsolicit(struct in6_addr *addr);
char *alloc_ndadvert(struct victim *svic, struct victim *dvic);
