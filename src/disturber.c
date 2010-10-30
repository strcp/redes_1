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

#include <packets.h>

#define DEBUG 0
#define PRINTABLE_ETHADDR(dest, addr) sprintf(dest, \
					"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", \
					(unsigned char)addr[0], \
					(unsigned char)addr[1], \
					(unsigned char)addr[2], \
					(unsigned char)addr[3], \
					(unsigned char)addr[4], \
					(unsigned char)addr[5]);

typedef struct device_info {
	int index;
	char name[IFNAMSIZ];
	unsigned int ifa_flags;
	struct sockaddr_in ipv4;
	struct sockaddr_in6 ipv6;
	struct ether_addr hwaddr;
} device_info;

struct device_info device;

static int raw_socket(int proto) {
	int rawsock;

	if ((rawsock = socket(PF_PACKET, SOCK_RAW, htons(proto))) < 0) {
		perror("Error creating raw socket: ");
		exit(-1);
	}

	return rawsock;
}

void load_device_info(const char *dev_name) {
	struct ifaddrs *ifaddr, *ifa;
	struct ifreq ifr;
	int sk;

	if (!dev_name) {
		printf("No device name.\n");
		exit(EXIT_FAILURE);
	}

	strncpy(device.name, dev_name, IFNAMSIZ);

	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs: ");
		exit(EXIT_FAILURE);
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (strcmp(dev_name, ifa->ifa_name) == 0) {
			if (ifa->ifa_addr->sa_family == AF_INET6)
				device.ipv6 = *(struct sockaddr_in6 *)(ifa->ifa_addr);
			else if (ifa->ifa_addr->sa_family == AF_INET)
				device.ipv4 = *(struct sockaddr_in *)(ifa->ifa_addr);

			if (ifa->ifa_flags != device.ifa_flags)
				device.ifa_flags = ifa->ifa_flags;
		}
	}
	freeifaddrs(ifaddr);

	strcpy(ifr.ifr_name, dev_name);
	if ((sk = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("Can't open socket: ");
		exit(EXIT_FAILURE);
	}

	/* First Get the Interface Index  */
	if ((ioctl(sk, SIOCGIFINDEX, &ifr)) == -1) {
		perror("Error getting Interface index: ");
		exit(EXIT_FAILURE);
	}

	device.index = ifr.ifr_ifindex;

	/* Get hwaddr information */
	if ((ioctl(sk, SIOCGIFHWADDR, &ifr)) == -1) {
		perror("Error getting mac address information: ");
		exit(EXIT_FAILURE);
	}

	memcpy(device.hwaddr.ether_addr_octet, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
}

static void dump_device_info(void) {
	char host[255];

	printf("- DEVICE DUMP -\n");
	printf("Name: %s\n", device.name);
	printf("Index: %i\n", device.index);
	printf("Flags: 0x%X\n", device.ifa_flags);

	inet_ntop(AF_INET6, &(device.ipv6.sin6_addr), host, 255);
	printf("IPv6: %s\n", host);

	inet_ntop(AF_INET, &(device.ipv4.sin_addr), host, 255);
	printf("IPv4: %s\n", host);

	printf("HWAddr: %s\n\n", ether_ntoa((struct ether_addr *)&device.hwaddr));
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

void debug_packet(unsigned char *packet, int len) {
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
	unsigned char packet_buffer[2048];
	struct sockaddr_ll packet_info;
	char *server_victim;
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
	bind_socket_to_device(argv[1], raw);

	/* Get number of packets to sniff from user */
	server_victim = argv[2];
	printf("Server to attack: %s\n", server_victim);

	/* Start Sniffing and print Hex of every packet */
	while (1) {
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
