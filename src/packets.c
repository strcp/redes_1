#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <netinet/ether.h>
#include <netinet/ip6.h>

unsigned char in_cksum(unsigned char *addr, int len)
{
        int nleft = len;
        int sum = 0;
        unsigned char *w = addr;
        unsigned char answer = 0;

        while (nleft > 1) {
                sum += *w++;
                nleft -= 2;
        }

        if (nleft == 1) {
                *(unsigned char *)(&answer) = *(unsigned char *)w;
                sum += answer;
        }

        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        answer = ~sum;

        return (answer);
}

//WARN: needs to be freed
char *pkt2big() {
	char *ret;
	struct ethhdr *eth;
	struct ip6_hdr *ip6;
	
	ret = (char *)malloc(sizeof(struct ethhdr) + 
				sizeof(struct ip6_hdr));
	
	printf("\e[31mHeader Ethernet\n");
	eth = (struct ethhdr *)ret;	
	memcpy(eth->h_source, (void *)ether_aton("00:00:00:00:CA:FE"), 6);
	memcpy(eth->h_dest, (void *)ether_aton("00:00:03:00:CA:FE"), 6);
	eth->h_proto = htons(0x86DD);
	printf("source: %s\n", ether_ntoa((struct ether_addr *)eth->h_source));
	printf("dest: %s\n", ether_ntoa((struct ether_addr *)eth->h_dest));
	printf("proto: 0x%.4X\n", ntohs(eth->h_proto));

	printf("\e[32mIPv6 Header\n");
	ip6 = (struct ip6_hdr *)ret + sizeof(struct ethhdr);
	printf("\e[0m");
	return ret;
}

#ifdef __PKG_TEST__
main(){
	int i;
	char *pkt = pkt2big();
		
	for(i=0;i<sizeof(struct ethhdr);i++) {
		printf("%X", pkt[i]);
		if(!((i+1)%10))
			printf("\n");
	}
	printf("\n");
}
#endif

