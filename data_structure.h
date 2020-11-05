#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <stdint.h>

#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_hash.h>
#define RECORD_ENTIRES 100000
//data structure secsion
struct compo_keyV4
{
	uint32_t ipv4_addr;
	uint32_t ipv4_addr_dst;
	uint8_t l3_pro;
	uint16_t src_port;
	uint16_t dst_port;
}__rte_cache_aligned;
struct usage_stat{
	uint64_t n_pkt;
	uint64_t size_of_this_p;
}__rte_cache_aligned;

extern struct compo_keyV4 key_list[RECORD_ENTIRES][2];
extern struct compo_keyV4 key_list_cli[RECORD_ENTIRES][2];

void write_log(struct rte_hash *tb,char *target,struct usage_stat data[][2],int curr_tb);