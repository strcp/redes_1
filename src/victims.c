/******************************************************************
 * Data : 30.11.2010
 * Disciplina   : Redes - PUCRS
 * Professora	: Ana Benso
 *
 * Autores  : Cristiano Bolla Fernandes
 *          : Benito Michelon
 *****************************************************************/

#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>

#include <disturber.h>
#include <packets.h>
#include <device.h>
#include <communication.h>

void debug_vivtim(struct victim *cli) {
	char buf[INET6_ADDRSTRLEN];

	if (!victim_info_complete(cli)) {
		printf("Client victim not loaded.\n");
		return;
	}

	printf("HWAddr: %s\n", ether_ntoa(&(cli->hwaddr)));
	memset(buf, 0, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, cli->ipv6.s6_addr, buf, INET6_ADDRSTRLEN);
	printf("IPv6: %s\n", buf);
}

int victim_info_complete(struct victim *vic) {
	struct ether_addr eth;
	struct in6_addr ipv6;

	memset(&eth, 0, sizeof(struct ether_addr));
	memset(&ipv6, 0, sizeof(struct in6_addr));

	if (!vic || !memcmp(&vic->hwaddr, &eth, sizeof(struct ether_addr)) ||
		!memcmp(&vic->ipv6, &ipv6, sizeof(struct in6_addr)))
		return 0;

	return 1;
}

void populate_victim(char *pkt) {
	struct ethhdr *eth;
	struct ip6_hdr *ip6;

	eth = (struct ethhdr *)pkt;
	ip6 = (struct ip6_hdr *)((char *)eth + sizeof(struct ethhdr));

	printf("Starting victim's structure\n");

	memcpy(&cvictim.ipv6, &ip6->ip6_src, sizeof(struct in6_addr));
	memcpy(&cvictim.hwaddr, &eth->h_source, ETH_ALEN);

	debug_vivtim(&cvictim);
}

void init_victim(struct victim *vic, const char *address) {
	char addr[INET6_ADDRSTRLEN];
	char *pkt;

	if (inet_pton(AF_INET6, address, &vic->ipv6) <= 0) {
		printf("Error setting victim's address\n");
		exit(EXIT_FAILURE);
	}

	inet_ntop(AF_INET6, &vic->ipv6, addr, INET6_ADDRSTRLEN);
	printf("Sending Neighbor Solicitation to %s\n", addr);

	pkt = alloc_ndsolicit(&vic->ipv6);
	send_packet(pkt);

	if (pkt)
		free(pkt);
}
