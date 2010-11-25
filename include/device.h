/******************************************************************
 * Data : 30.11.2010
 * Disciplina   : Redes - PUCRS
 * Professora	: Ana Benso
 *
 * Autores  : Cristiano Bolla Fernandes
 *          : Benito Michelon
 *****************************************************************/

/**
 * @ingroup device
 * @{
 */
#include <net/if.h>

/** Estrutura com a informação sobre o device utilizado. */
typedef struct device_info {
	int index;					/**< Índice do device */
	char name[IFNAMSIZ];		/**< Nome da interface */
	unsigned int ifa_flags;		/**< Flags do device */
	struct in_addr ipv4;		/**< Endereço IPv4 do device */
	struct in6_addr ipv6;		/**< Endereço IPv6 do device */
	struct ether_addr hwaddr;	/**< MAC address do device */
} device_info;

struct device_info device;

void load_device_info(const char *dev_name);
void dump_device_info(void);
/** @} */
