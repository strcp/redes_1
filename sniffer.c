#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <features.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>


int raw_socket(int proto) {
	int rawsock;

	if ((rawsock = socket(PF_PACKET, SOCK_RAW, htons(proto))) < 0) {
		perror("Error creating raw socket: ");
		exit(-1);
	}

	return rawsock;
}

int bind_socket_to_device(char *device, int rawsock, int protocol) {
	struct packet_mreq *pkt;
	struct ifreq ifr;

	bzero(&ifr, sizeof(ifr));

	/* First Get the Interface Index  */
	strncpy((char *)ifr.ifr_name, device, IFNAMSIZ);
	if ((ioctl(rawsock, SIOCGIFINDEX, &ifr)) == -1) {
		printf("Error getting Interface index !\n");
		exit(-1);
	}

	/* Go promisc */
	strncpy(ifr.ifr_name, device, IFNAMSIZ);
	if ((ioctl(rawsock, SIOCGIFFLAGS, &ifr)) < 0) {
		perror("Error: ");
		exit(-1);
	}

	ifr.ifr_flags |= IFF_PROMISC;
	if ((ioctl(rawsock, SIOCSIFFLAGS, &ifr)) < 0) {
		perror("Error: ");
		exit(-1);
	}

	pkt = (struct packet_mreq *) malloc(sizeof(struct packet_mreq));
	memset((struct packet_mreq *)pkt, 0, sizeof(struct packet_mreq));
	pkt->mr_ifindex = ifr.ifr_ifindex;
	pkt->mr_type = PACKET_MR_PROMISC;
	setsockopt(rawsock, SOL_PACKET, PACKET_MR_PROMISC, (char *)&pkt,
									sizeof(struct packet_mreq));

	return 1;
}

void PrintPacketInHex(unsigned char *packet, int len) {
	unsigned char *p = packet;
	struct ethhdr *eth;
	struct ipv6hdr *ip6;
	struct icmp6hdr *icmpv6;
	char addr[16];

	printf("\n- PACKET START -\n");

	eth = (struct ethhdr *)packet;
	ip6 = (struct ipv6hdr *)(packet + sizeof(struct ethhdr));

	if (ip6->daddr.s6_addr) {
		inet_ntop(AF_INET6, ip6->daddr.s6_addr, addr, sizeof(struct in6_addr));
		printf("To: %s\n", addr);
	}

	memset(addr, 0, 16);

	if (ip6->saddr.s6_addr) {
		inet_ntop(AF_INET6, ip6->saddr.s6_addr, addr, sizeof(struct in6_addr));
		printf("From: %s\n", addr);
	}

	switch (ip6->nexthdr) {
		case IPPROTO_ICMPV6:
			icmpv6 = (struct icmp6hdr *)((char *)ip6 + sizeof(struct ipv6hdr));
			printf("ICMPv6 DEBUG:\n");
			printf("Type: %d\n", icmpv6->icmp6_type);
			break;
		default:
			break;
	}
/*
	while (len--) {
		printf("%.2x ", *p);
		p++;
	}
*/
	printf("- PACKET END -\n\n");
}

main(int argc, char **argv)
{
	int raw;
	unsigned char packet_buffer[2048];
	int len;
	int packets_to_sniff;
	struct sockaddr_ll packet_info;
	struct sockaddr from;
	int packet_info_size = sizeof(packet_info);

	/* create the raw socket */
	raw = raw_socket(ETH_P_IPV6);

	/* Bind socket to interface and going promisc */
	bind_socket_to_device(argv[1], raw, ETH_P_IPV6);

	/* Get number of packets to sniff from user */
	packets_to_sniff = atoi(argv[2]);

	/* Start Sniffing and print Hex of every packet */
	while (packets_to_sniff--) {
		if ((len = recvfrom(raw, packet_buffer, 2048, 0, (struct sockaddr*)&packet_info, &packet_info_size)) == -1) {
			perror("Recv from returned -1: ");
			exit(-1);
		} else {
			/* Packet has been received successfully !! */
			PrintPacketInHex(packet_buffer, len);
		}
	}

	return 0;
}


