#ifndef __PKT__
#define __PKT__

unsigned short icmp6_crc(struct icmp6_hdr *hdr, struct ip6_hdr *dst);
char *alloc_pkt2big();
#endif
