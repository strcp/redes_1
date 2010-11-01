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

void packet_action(char *packet) {
	struct ethhdr *eth;
	struct ip6_hdr *ip6;
	struct icmp6_hdr *icmpv6;
	struct tcphdr *tcp;
	unsigned short crc;

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
				printf("Packet Hijacked? :-)\n");
			}
			break;
		default:
			break;
	}
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
			packet_action(packet_buffer);
	}

	return 0;
}
