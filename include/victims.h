#include <pthread.h>

#include <netinet/in.h>
#include <netinet/ether.h>

typedef struct victim {
	struct ether_addr hwaddr;
	struct in_addr ipv4;
	struct in6_addr ipv6;
	int poisoned;
} victim;

#if 0
typedef struct cli_victim {
	struct cli_victim *nxt;
	struct victim *cv_victim;
	pthread_t poison_client;
} cli_victim;

#define hwaddr cv_victim.hwaddr
#define ipv4 cv_victim.ipv4
#define ipv6 cv_victim.ipv6
#define poisoned cv_victim.poisoned
#endif

struct victim svictim, *cvictim;

/* Lista de clients vitctims */
//struct cli_victim *cvictim;

void init_cvictim();
void init_svictim(const char *sv_address);

void debug_cvivtim(struct victim *cli);
/*struct victim *get_cvictim(struct ether_addr *hwaddr);
int add_cvictm(struct ethhdr *eth);*/
