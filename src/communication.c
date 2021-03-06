/******************************************************************
 * Data : 30.11.2010
 * Disciplina   : Redes - PUCRS
 * Professora	: Ana Benso
 *
 * Autores  : Cristiano Bolla Fernandes
 *          : Benito Michelon
 *****************************************************************/

/**
 * @defgroup communication Criação de sockets e envio de pacotes
 * @brief Criação de sockets e envio de pacotes
 * @{
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/ioctl.h>

#include <linux/if_packet.h>
#include <netinet/if_ether.h>

#include <device.h>
#include <packets.h>

/**
 * Cria um raw socket.
 * @param proto Protocolo do socket.
 * @return Retorna o descritor do socket criado.
 */
static int raw_socket(int proto) {
	int rawsock;

	if ((rawsock = socket(PF_PACKET, SOCK_RAW, htons(proto))) < 0) {
		perror("Error creating raw socket: ");
		exit(-1);
	}

	return rawsock;
}

/**
 * Atrela um socket a um device.
 * @param device Interface do device a ser atrelado.
 * @param rawsock Descritor da socket.
 * @return Retorna > 0 em sucesso e < 0 em falha.
 */
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

/**
 * Envia pacote de dados desde os headers ethernet.
 * @param pkt Pacote com dados desde os headers ethernet.
 * @return Retorna > 0 em sucesso e < 0 em falha.
 */
int send_packet(char *pkt) {
	struct ethhdr *eth;
	struct ip6_hdr *ip6;
	struct sockaddr_ll to;
	int raw;
	unsigned int len;

	if (pkt == NULL)
		return 0;

	eth = (struct ethhdr *)pkt;
	ip6 = (struct ip6_hdr *)((char *)eth + sizeof(struct ethhdr));

	len = ntohs(ip6->ip6_plen) + sizeof(struct ip6_hdr) + sizeof(struct ethhdr);

	if ((raw = raw_socket(ETH_P_ALL)) < 0) {
		perror("Error creating socket: ");
		return raw;
	}

	memset(&to, 0, sizeof(struct sockaddr_ll));
	to.sll_family = PF_PACKET;
	to.sll_protocol = htons(ETH_P_ALL);
	to.sll_ifindex = device.index;
	memcpy(to.sll_addr, eth->h_dest, ETH_ALEN);

	if ((sendto(raw, pkt, len, 0, (struct sockaddr *)&to, sizeof(to))) < 0) {
		perror("Error sending packet: ");
		close(raw);
		return -1;
	}
	close(raw);

	return 1;
}

/**
 * Cria um socket promisc.
 * @param dev_name Interface que ficará promisc..
 * @return Retorna socket em promisc mode.
 */
int get_promisc_socket(char *dev_name) {
	int raw;

	/* create the raw socket */
	raw = raw_socket(ETH_P_IPV6);

	/* Bind socket to interface and going promisc */
	bind_socket_to_device(dev_name, raw);

	return raw;
}
/** @} */
