#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <stdint.h>
#include <yaml.h>

#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_hash.h>
#include <rte_jhash.h>
/*
	Declare most use variable in this file
*/
#define RECORD_ENTIRES 100000
#define REC_GLOBAL_LIM 3000000
//data structure secsion
struct compo_keyV4
{
	uint32_t ipv4_addr;
	uint32_t ipv4_addr_dst;
	uint8_t l3_pro;
	uint16_t src_port;
	uint16_t dst_port;
} __rte_cache_aligned;
struct compo_keyV6
{
	uint8_t ipv6_addr[16];
	uint8_t ipv6_addr_dst[16];
	uint8_t l3_pro;
	uint16_t src_port;
	uint16_t dst_port;
} __rte_cache_aligned;

struct usage_stat{
	uint64_t n_pkt;
	uint64_t size_of_this_p;
	uint8_t is_alert;
}__rte_cache_aligned;
struct node{
	uint32_t ipaddr;
	int index;
	TAILQ_ENTRY(node) nodes;
};
typedef TAILQ_HEAD(head_s, node) head_t;
extern int isVerbose;
extern uint64_t time_peroid;//use for counting cycle
extern uint64_t real_seconds;

extern struct compo_keyV4 key_list[RECORD_ENTIRES][2];
extern struct compo_keyV4 key_list_cli[RECORD_ENTIRES][2];
extern struct compo_keyV6 key_list6[RECORD_ENTIRES][2];
extern struct compo_keyV6 key_list_cli6[RECORD_ENTIRES][2];

extern struct usage_stat ipv4_stat[RECORD_ENTIRES][2];
extern struct usage_stat ipv4_cli[RECORD_ENTIRES][2];
extern struct usage_stat ipv6_stat[RECORD_ENTIRES][2];

struct diy_hash{
	uint64_t n_pkt;
	uint64_t size_of_this_p;
	uint8_t is_alert;
	uint32_t realaddr;
}__rte_cache_aligned;
extern uint32_t lim_addr[RECORD_ENTIRES];
extern int elem_lim;
extern struct diy_hash  host_lim[RECORD_ENTIRES];
extern struct diy_hash host_stat[RECORD_ENTIRES][2];
extern head_t head;
void write_log_v4(struct rte_hash *tb,char *target,int curr_tb);
void write_log_v6(struct rte_hash *tb,char *target,int curr_tb);
const char* show_IPv4(uint32_t addr);
int init_host_lim();