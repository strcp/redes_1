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


void init_cvictim() {
	cvictim = NULL;
}

void debug_cvivtim(struct victim *cli) {
	char buf[INET6_ADDRSTRLEN];

	printf("HWADDR: %s\n", ether_ntoa(&(cli->hwaddr)));
	memset(buf, 0, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, cli->ipv6.s6_addr, buf, INET6_ADDRSTRLEN);
	printf("IPv6: %s\n", buf);
}

struct cli_victim *get_cvictim(struct ethhdr *eth) {
	struct cli_victim *cli;
	struct ip6_hdr *ip6;

	ip6 = (struct ip6_hdr *)((char *)eth + sizeof(struct ethhdr));

	for (cli = cvictim; cli; cli = cli->nxt) {
		printf("entrei");
		if (memcmp(&(cli->cv_victim.hwaddr), &(eth->h_source),
							sizeof(struct ether_addr)) == 0) {
			printf("Cliente existente\n");

			return cli;
		}
	}

	printf("Cliente inexistente\n");

	cli = cvictim;
	cvictim = (struct cli_victim *)malloc(sizeof(struct cli_victim));
	cvictim->nxt = cli;

	memcpy(&(cvictim->cv_victim.hwaddr), &(eth->h_source), ETH_ALEN);
	//cvictim->cv_victim.ipv4
	memcpy(&(cvictim->cv_victim.ipv6), &(ip6->ip6_src), INET6_ADDRSTRLEN);
	cvictim->cv_victim.poisoned = 0;
	//cvictim->th = (struct pthread_t *)malloc(sizeof(struct pthread_t));

	return cvictim;
}

void *th_func(void *conn) {
	//poisoning
	printf("oiaeu\n");

	pthread_exit((void*)EXIT_SUCCESS);
}
