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
#include <device.h>

void load_device_info(const char *dev_name) {
	struct ifaddrs *ifaddr, *ifa;
	struct ifreq ifr;
	struct sockaddr_in6 *sin6 = NULL;
	struct sockaddr_in *sin = NULL;
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
			if (ifa->ifa_addr->sa_family == AF_INET6) {
				sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
				memcpy(&device.ipv6, &sin6->sin6_addr, sizeof(struct in6_addr));
			} else if (ifa->ifa_addr->sa_family == AF_INET) {
				sin = (struct sockaddr_in *)ifa->ifa_addr;
				memcpy(&device.ipv4, &sin->sin_addr, sizeof(struct in_addr));
			}

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

void dump_device_info(void) {
	char host[INET6_ADDRSTRLEN];

	printf("Device information\n");
	printf("name: %s\n", device.name);
	printf("index: %i\n", device.index);

	inet_ntop(AF_INET6, &(device.ipv6), host, INET6_ADDRSTRLEN);
	printf("IPv6: %s\n", host);

	inet_ntop(AF_INET, &(device.ipv4), host, INET_ADDRSTRLEN);
	printf("IPv4: %s\n", host);

	printf("HWAddr: %s\n\n", ether_ntoa((struct ether_addr *)&device.hwaddr));
}
