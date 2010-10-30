#include <netinet/in.h>
#include <netinet/ether.h>

typedef struct victim {
	struct ether_addr hwaddr;
	struct in_addr ipv4;
	struct in6_addr ipv6;
	int poisoned;
} victim;

struct victim svictim;
struct victim cvictim;
