#include <netinet/in.h>
#include <netinet/ether.h>

typedef struct victim {
	struct sockaddr_in ipv4;
	struct sockaddr_in6 ipv6;
	struct ether_addr hwaddr;
	int poisoned;
} victim;

struct victim svictim;
struct victim cvictim;
