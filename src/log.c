#include <stdio.h>
#include <unistd.h>
#include <time.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <netinet/ether.h>
#include <netinet/ip6.h>

#include <log.h>

void log_packet(const char *packet) {
	struct ethhdr *eth;
	struct ip6_hdr *ip6;
	struct pcaprec_hdr_s rec;
	struct pcap_hdr_s global;
	int fd, len;
	time_t sec;

	if (packet == NULL)
		return;

	sec = time(NULL);
	len = 0;

	/* FIXME: Path hardcoded :-) */
	if (access("test.pcap", F_OK) < 0) {
		/* Pcap global header */
		global.magic_number = 0xa1b2c3d4;
		global.version_major = 2;
		global.version_minor = 4;
		global.thiszone = 0;	/* UTC */
		global.sigfigs = 0;
		global.snaplen = 65535;
		global.network = 1;		/* Ethernet */

		len = sizeof(struct pcap_hdr_s);
	}

	if (!(fd = open("test.pcap", O_WRONLY | O_APPEND | O_CREAT))) {
		perror("Logfile ");

		return;
	}

	if (len > 0)	/* Write global header */
		write(fd, &global, sizeof(struct pcap_hdr_s));

	eth = (struct ethhdr *)packet;
	ip6 = (struct ip6_hdr *)((char *)eth + sizeof(struct ethhdr));

	/* Pcap record header */
	rec.ts_sec = sec;
	rec.ts_usec = 0;
	rec.incl_len =  ntohs(ip6->ip6_plen) +
					sizeof(struct ip6_hdr) +
					sizeof(struct ethhdr);
	rec.orig_len = rec.incl_len;

	/* Write record header */
	write(fd, &rec, sizeof(struct pcaprec_hdr_s));

	len += ntohs(ip6->ip6_plen) +
			sizeof(struct ip6_hdr) +
			sizeof(struct ethhdr);

	write(fd, packet, len);
	close(fd);
}
