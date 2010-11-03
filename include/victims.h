#include <netinet/in.h>
#include <netinet/ether.h>

#include <pthread.h>
#include <signal.h>

typedef struct victim {
	struct ether_addr hwaddr;
	struct in_addr ipv4;
	struct in6_addr ipv6;
	int poisoned;
} victim;

typedef struct cli_victim {
	struct cli_victim *nxt;
	struct victim cv_victim;
	pthread_t th;
} cli_victim;
#if 0
#define hwaddr cv_victim.hwaddr
#define ipv4 cv_victim.ipv4
#define ipv6 cv_victim.ipv6
#define poisoned cv_victim.poisoned
#endif
struct victim svictim;
struct cli_victim *cvictim;
