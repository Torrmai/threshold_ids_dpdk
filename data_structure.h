#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <stdint.h>

#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_hash.h>
//data structure secsion
struct compo_keyV4
{
	uint32_t ipv4_addr;
	uint8_t l3_pro;
	uint16_t port;
}__rte_cache_aligned;
struct usage_stat{
	uint16_t src_port;
	uint64_t n_pkt;
	uint64_t size_of_this_p;
}__rte_cache_aligned;

extern struct compo_keyV4 key_list[2000][2];

void write_log(struct rte_hash *tb,char *target,int numelem,struct usage_stat data[][2],int curr_tb);