#include <pthread.h>

#include <netinet/in.h>
#include <netinet/ether.h>

typedef struct victim {
	struct ether_addr hwaddr;
	struct in_addr ipv4;
	struct in6_addr ipv6;
	int poisoned;
} victim;

struct victim svictim, cvictim;

void init_victim(struct victim *vic, const char *address);

void debug_vivtim(struct victim *cli);
int victim_info_complete(struct victim *vic);
void populate_victim(char *pkt);
