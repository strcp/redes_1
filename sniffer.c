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


int CreateRawSocket(int protocol_to_sniff)
{
	int rawsock;

	if ((rawsock = socket(PF_PACKET, SOCK_RAW, htons(protocol_to_sniff)))== -1) {
		perror("Error creating raw socket: ");
		exit(-1);
	}

	return rawsock;
}

int BindRawSocketToInterface(char *device, int rawsock, int protocol) {
	struct sockaddr_ll sll;
	struct ifreq ifr;

	bzero(&sll, sizeof(sll));
	bzero(&ifr, sizeof(ifr));

	/* First Get the Interface Index  */
	strncpy((char *)ifr.ifr_name, device, IFNAMSIZ);
	if ((ioctl(rawsock, SIOCGIFINDEX, &ifr)) == -1) {
		printf("Error getting Interface index !\n");
		exit(-1);
	}

	/* Bind our raw socket to this interface */
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	sll.sll_protocol = htons(protocol);

	if ((bind(rawsock, (struct sockaddr *)&sll, sizeof(sll))) == -1) {
		perror("Error binding raw socket to interface\n");
		exit(-1);
	}

	return 1;
}

void PrintPacketInHex(unsigned char *packet, int len) {
	unsigned char *p = packet;
	struct ethhdr *eth;
	struct ipv6hdr *ip6;
	char daddr[16];

	printf("\n\n---------Packet---Starts----\n\n");

	eth = (struct ethhdr *)packet;
	ip6 = (struct ipv6hdr *)(packet + sizeof(struct ethhdr));

	if (ip6->daddr.s6_addr) {
		inet_ntop(AF_INET6, ip6->daddr.s6_addr, daddr, sizeof(struct in6_addr));
		printf("Debug: %s\n", daddr);
	}
	printf("Debug: %s\n", eth->h_dest);
	printf("Debug: %d\n", ip6->version);
	while (len--) {
		printf("%.2x ", *p);
		p++;
	}

	printf("\n\n--------Packet---Ends-----\n\n");
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

	raw = CreateRawSocket(ETH_P_IPV6);

	/* Bind socket to interface */

	BindRawSocketToInterface(argv[1], raw, ETH_P_IPV6);

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


