#include <net/if.h>

typedef struct device_info {
	int index;
	char name[IFNAMSIZ];
	unsigned int ifa_flags;
	struct in_addr ipv4;
	struct in6_addr ipv6;
	struct ether_addr hwaddr;
} device_info;

struct device_info device;

void load_device_info(const char *dev_name);
void dump_device_info(void);
