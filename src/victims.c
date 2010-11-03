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

#include <packets.h>
#include <victims.h>
#include <device.h>


void debug_cvivtim(struct victim *cli) {
	char buf[INET6_ADDRSTRLEN];

	printf("HWADDR: %s\n", ether_ntoa(&(cli->hwaddr)));
	memset(buf, 0, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, cli->ipv6.s6_addr, buf, INET6_ADDRSTRLEN);
	printf("IPv6: %s\n", buf);
}

struct victim *get_cvictim(struct ether_addr *hwaddr) {
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

void init_cvictim() {
	cvictim = NULL;
}

void cleanup_cvictims() {
	struct cli_victim *cli, *aux;

	aux = NULL;

	for (cli = cvictim, aux = cli->nxt; cli; cli = aux) {
		free(cli);
	}

	cvictim = NULL;
}
