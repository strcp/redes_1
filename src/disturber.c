#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

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

int raw_socket(int proto) {
	int rawsock;

	if ((rawsock = socket(PF_PACKET, SOCK_RAW, htons(proto))) < 0) {
		perror("Error creating raw socket: ");
		exit(-1);
	}

	return rawsock;
}

int bind_socket_to_device(char *device, int rawsock) {
	struct packet_mreq *pkt;
	struct ifreq ifr;

	bzero(&ifr, sizeof(ifr));

	strncpy((char *)ifr.ifr_name, device, IFNAMSIZ);

	/* First Get the Interface Index  */
	if ((ioctl(rawsock, SIOCGIFINDEX, &ifr)) == -1) {
		printf("Error getting Interface index !\n");
		exit(-1);
	}

	/* Go promisc */
	if ((ioctl(rawsock, SIOCGIFFLAGS, &ifr)) < 0) {
		perror("Error: ");
		exit(-1);
	}

	ifr.ifr_flags |= IFF_PROMISC;
	if ((ioctl(rawsock, SIOCSIFFLAGS, &ifr)) < 0) {
		perror("Error: ");
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

void debug_packet(unsigned char *packet, int len) {
	struct ethhdr *eth;
	struct ip6_hdr *ip6;
	struct icmp6_hdr *icmpv6;
	struct tcphdr *tcp;
	char addr[INET6_ADDRSTRLEN];

	printf("\n- PACKET START (%d) -\n", len);

	eth = (struct ethhdr *)packet;
	ip6 = (struct ip6_hdr *)(packet + sizeof(struct ethhdr));

	if (ip6->ip6_dst.s6_addr) {
		inet_ntop(AF_INET6, ip6->ip6_dst.s6_addr, addr, INET6_ADDRSTRLEN);
		printf("To: %s\n", addr);
	}

	memset(addr, 0, INET6_ADDRSTRLEN);

	if (ip6->ip6_src.s6_addr) {
		inet_ntop(AF_INET6, ip6->ip6_src.s6_addr, addr, INET6_ADDRSTRLEN);
		printf("From: %s\n", addr);
	}

	switch (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
		case IPPROTO_ICMPV6:
			icmpv6 = (struct icmp6_hdr *)((char *)ip6 + sizeof(struct ip6_hdr));
			printf("ICMPv6 DEBUG:\n");
			printf("Type: %d\n", icmpv6->icmp6_type);
			break;
		case IPPROTO_TCP:
			tcp = (struct tcphdr *)((char *)ip6 + sizeof(struct ip6_hdr));
			printf("TCP DEBUG:\n");
			printf("Dest Port: %d\n", tcp->dest);
			printf("Src Port: %d\n", tcp->source);
			break;
		default:
			break;
	}
	printf("- PACKET END -\n\n");
}

int main(int argc, char **argv) {
	int raw;
	unsigned char packet_buffer[2048];
	int len;
	int packets_to_sniff;
	struct sockaddr_ll packet_info;
	int packet_info_size = sizeof(packet_info);


	if (argc < 3) {
		printf("Usage: %s <interface> <num of packets>\n", argv[0]);
		exit(0);
	}

	/* create the raw socket */
	raw = raw_socket(ETH_P_IPV6);

	/* Bind socket to interface and going promisc */
	bind_socket_to_device(argv[1], raw);

	/* Get number of packets to sniff from user */
	packets_to_sniff = atoi(argv[2]);

	/* Start Sniffing and print Hex of every packet */
	while (packets_to_sniff--) {
		if ((len = recvfrom(raw, packet_buffer, 2048, 0,
							(struct sockaddr*)&packet_info,
							(socklen_t *)&packet_info_size)) == -1) {
			perror("Recv from returned -1: ");
			exit(-1);
		} else {
			debug_packet(packet_buffer, len);
		}
	}

	return 0;
}
