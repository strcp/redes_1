/******************************************************************
 * Data : 30.11.2010
 * Disciplina   : Redes - PUCRS
 * Professora	: Ana Benso
 *
 * Autores  : Cristiano Bolla Fernandes
 *          : Benito Michelon
 *****************************************************************/

/**
 * @ingroup victims
 * @{
 */
#include <pthread.h>

#include <netinet/in.h>
#include <netinet/ether.h>

/** Estrutura com a informação sobre uma vítima. */
typedef struct victim {
	struct ether_addr hwaddr;	/**< MAC da vítima */
	struct in_addr ipv4;		/**< Endereço IPv4 da vítima */
	struct in6_addr ipv6;		/**< Endereço IPv6 da vítima */
	int poisoned;				/**< Flag que indica se a vítima já foi "poisoned" */
} victim;

struct victim svictim, cvictim;

void init_victim(struct victim *vic, const char *address);

void debug_vivtim(struct victim *cli);
int victim_info_complete(struct victim *vic);
void populate_victim(char *pkt);
/** @} */
