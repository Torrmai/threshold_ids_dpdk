#include <time.h>
#include <sys/time.h>
#include <signal.h>
#include <stdint.h>
#include <inttypes.h>
#include <getopt.h>
#include <stdbool.h>
#include <syslog.h>
#include <math.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_eth_ctrl.h>
#include "data_structure.h"


#define MAX_RX_QUEUE_PER_LCORE 1024
#define MAX_TX_QUEUE_PER_LCORE 1024
#define BURST_TX_DRAIN_US 100
#define MEMPOOL_CACHE_SIZE 256
#define NB_MBUF(nports) RTE_MAX(	\
	(nports*nb_rx_queue*nb_rxd +		\
	nports*nb_lcores*64 +	\
	nports*3*nb_txd +		\
	nb_lcores*MEMPOOL_CACHE_SIZE),		\
	(unsigned)8192)
#define MAX_PKT_BURST 128
#define PREFETCH_OFFSET	3
#define CMD_LINE_OPT_MAC_UPDATING "mac-updating"
#define CMD_LINE_OPT_NO_MAC_UPDATING "no-mac-updating"
static uint16_t nb_rxd = 128;
static uint16_t nb_txd = 512;

static int mac_updating = 1;
static volatile bool force_quit;
static struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];
typedef struct lcore_rx_queue lcore_rx_queue;
struct lcore_rx_queue{
	uint8_t queue_id;
	uint8_t port_id;
}__rte_cache_aligned;
typedef struct lcore_params lcore_params;
struct lcore_params {
	uint8_t port_id;
	uint8_t queue_id;
	uint8_t lcore_id;
} __rte_cache_aligned;
static lcore_params lcore_map_arr_default[] ={
	{0,0,0},
	{0,0,1},
	{0,1,2},
	{0,2,3},
	{1,0,0},
	{1,0,1},
	{1,1,2},
	{1,2,3}
};
//core 0 is used by linux os
static struct lcore_params *lcore_params_ptr = lcore_map_arr_default;
static uint16_t nb_lcore_params = sizeof(lcore_map_arr_default)/sizeof(lcore_map_arr_default[0]);
typedef struct lcore_conf lcore_conf;
struct lcore_conf{
	uint16_t n_rx_queue;
	unsigned rx_port_list[RTE_MAX_ETHPORTS];
	struct lcore_rx_queue rx_queue_list[MAX_RX_QUEUE_PER_LCORE];
	uint16_t n_tx_port;
	uint16_t tx_port_id[RTE_MAX_ETHPORTS];
	uint16_t tx_queue_id[MAX_TX_QUEUE_PER_LCORE];
}__rte_cache_aligned;
static struct lcore_conf lcore_conf_arr[RTE_MAX_LCORE];

static struct rte_eth_conf port_conf = {
    .rxmode = {
        .mq_mode = ETH_MQ_RX_RSS,
    },
    .rx_adv_conf = {
        .rss_conf = {
        	.rss_hf = ETH_RSS_IP |
              		  ETH_RSS_TCP |
              		  ETH_RSS_UDP |
              		  ETH_RSS_SCTP,
        },
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
    },
};
static struct rte_mempool *pktmbuf_pool[RTE_MAX_ETHPORTS];
static struct rte_ether_addr port_addr[RTE_MAX_ETHPORTS];
static struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS][3];
static const char short_options[]=
	"V:" /*turn on or off verbose mode*/
	"T:"/*set timer peroid*/
	"s:"/*sort by ...*/
	;
static const struct option lgopts[] = {
	{ CMD_LINE_OPT_MAC_UPDATING, no_argument, &mac_updating, 1},
	{ CMD_LINE_OPT_NO_MAC_UPDATING, no_argument, &mac_updating, 0},
	{NULL, 0, 0, 0}
};

//statistical related data type
struct basic_port_statistic{
	uint64_t rx_packet;
	uint64_t size;
}__rte_cache_aligned;
struct basic_port_statistic port_stat[RTE_MAX_ETHPORTS];
struct brief_data_info_elem
{
	uint64_t n_ipv4_pack;
	uint64_t server_pack_v4;
	uint64_t client_pack_v4;
	uint64_t ipv4_usage;
	uint64_t n_ipv6_pack;
	uint64_t server_pack_v6;
	uint64_t client_pack_v6;
	uint64_t ipv6_usage;
}__rte_cache_aligned;
struct brief_data_info_elem data_info[2];

struct max_mem{
	uint32_t ipv4_addr;
	uint8_t l3_pro;
	uint16_t port;
	uint16_t src_port;
	uint64_t n_pkt;
	uint64_t size_of_this_p;
};


struct usage_stat ipv4_stat[RECORD_ENTIRES][2];
struct usage_stat ipv4_cli[RECORD_ENTIRES][2];
struct usage_stat ipv6_stat[RECORD_ENTIRES][2];
struct compo_keyV4 key_list[RECORD_ENTIRES][2];
struct compo_keyV4 key_list_cli[RECORD_ENTIRES][2];
struct compo_keyV6 key_list6[RECORD_ENTIRES][2];
struct diy_hash host_stat[RECORD_ENTIRES][2];
const struct rte_hash *hash_tb[2];
const struct rte_hash *hash_tb_cli[2];
const struct rte_hash *hash_tb_v6[2];
const struct rte_hash *limit_hash;
uint64_t tcp_port_lim[65536];
uint64_t udp_port_lim[65536];
//struct rte_hash *hash_tb_v6_cli[2];

uint32_t numkey[] = {0,0};
uint32_t numkey_cli[] = {0,0};
uint32_t numkeyV6[] = {0,0};
unsigned n_port;
int elem_lim;
uint32_t lim_addr[RECORD_ENTIRES];
int isAdded = 1;
// init section

int sym_hash_enable(int port_id, uint32_t ftype, enum rte_eth_hash_function function)
{
    struct rte_eth_hash_filter_info info;
    int ret = 0;
    uint32_t idx = 0;
    uint32_t offset = 0;

    memset(&info, 0, sizeof(info));

    ret = rte_eth_dev_filter_supported(port_id, RTE_ETH_FILTER_HASH);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE,"RTE_ETH_FILTER_HASH not supported on port: %d",
                         port_id);
        return ret;
    }

    info.info_type = RTE_ETH_HASH_FILTER_GLOBAL_CONFIG;
    info.info.global_conf.hash_func = function;

    idx = ftype / UINT64_BIT;
    offset = ftype % UINT64_BIT;
    info.info.global_conf.valid_bit_mask[idx] |= (1ULL << offset);
    info.info.global_conf.sym_hash_enable_mask[idx] |=
                        (1ULL << offset);

    ret = rte_eth_dev_filter_ctrl(port_id, RTE_ETH_FILTER_HASH,
                                  RTE_ETH_FILTER_SET, &info);
    if (ret < 0)
    {
        rte_exit(EXIT_FAILURE,"Cannot set global hash configurations"
                        "on port %u", port_id);
        return ret;
    }

    return 0;
}

int sym_hash_set(int port_id, int enable)
{
    int ret = 0;
    struct rte_eth_hash_filter_info info;

    memset(&info, 0, sizeof(info));

    ret = rte_eth_dev_filter_supported(port_id, RTE_ETH_FILTER_HASH);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE,"RTE_ETH_FILTER_HASH not supported on port: %d",
                         port_id);
        return ret;
    }

    info.info_type = RTE_ETH_HASH_FILTER_SYM_HASH_ENA_PER_PORT;
    info.info.enable = enable;
    ret = rte_eth_dev_filter_ctrl(port_id, RTE_ETH_FILTER_HASH,
                        RTE_ETH_FILTER_SET, &info);

    if (ret < 0)
    {
        rte_exit(EXIT_FAILURE,"Cannot set symmetric hash enable per port "
                        "on port %u", port_id);
        return ret;
    }

    return 0;
}
int
init_mem(uint16_t portid, unsigned int nb_mbuf)
{
	unsigned lcore_id;
	char s[64];

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		if (pktmbuf_pool[portid]== NULL) {
			snprintf(s, sizeof(s), "mbuf_pool_%d:==",
				 portid);
			pktmbuf_pool[portid] =
				rte_pktmbuf_pool_create(s, nb_mbuf,
					MEMPOOL_CACHE_SIZE, 0,
					RTE_MBUF_DEFAULT_BUF_SIZE, 0);
			if (pktmbuf_pool[portid] == NULL)
				rte_exit(EXIT_FAILURE,
					"Cannot init mbuf pool\n");
		}
	}
	return 0;
}
static int
init_port(){
	struct lcore_conf *qconf;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf *txconf;
	struct rte_eth_conf local_port_conf;
	int ret;
	unsigned lcore_id;
	uint32_t nb_lcores;
	uint16_t queueid,portid;
	uint8_t nb_rx_queue,socketid,queue;
	nb_rx_queue = 3;
	nb_lcores = rte_lcore_count();
	RTE_ETH_FOREACH_DEV(portid){
		local_port_conf = port_conf;
		printf("Initializing port %"PRIu16"\n",portid);
		fflush(stdout);
		ret = rte_eth_dev_info_get(portid, &dev_info);
		if(ret != 0){
			rte_exit(EXIT_FAILURE,"Error geting info of port %u\n",portid);
		}
		ret = rte_eth_macaddr_get(portid,&ports_eth_addr[portid]);
		if(ret != 0){
			rte_exit(EXIT_FAILURE,"Error geting mac addr of port %u\n",portid);
		}
		local_port_conf.rx_adv_conf.rss_conf.rss_hf &=
			dev_info.flow_type_rss_offloads;
		if (local_port_conf.rx_adv_conf.rss_conf.rss_hf !=
				port_conf.rx_adv_conf.rss_conf.rss_hf) {
			printf("Port %u modified RSS hash function based on hardware support,"
				"requested:%#"PRIx64" configured:%#"PRIx64"\n",
				portid,
				port_conf.rx_adv_conf.rss_conf.rss_hf,
				local_port_conf.rx_adv_conf.rss_conf.rss_hf);
		}
		ret = rte_eth_dev_configure(portid, nb_rx_queue,
					(uint16_t)nb_lcores, &local_port_conf);// 3 queues for both rx and tx
		sym_hash_enable(portid, RTE_ETH_FLOW_NONFRAG_IPV4_TCP, RTE_ETH_HASH_FUNCTION_TOEPLITZ);
		sym_hash_enable(portid, RTE_ETH_FLOW_NONFRAG_IPV4_UDP, RTE_ETH_HASH_FUNCTION_TOEPLITZ);
		sym_hash_enable(portid, RTE_ETH_FLOW_FRAG_IPV4, RTE_ETH_HASH_FUNCTION_TOEPLITZ);
		sym_hash_enable(portid, RTE_ETH_FLOW_NONFRAG_IPV4_SCTP, RTE_ETH_HASH_FUNCTION_TOEPLITZ);
		sym_hash_enable(portid, RTE_ETH_FLOW_NONFRAG_IPV4_OTHER, RTE_ETH_HASH_FUNCTION_TOEPLITZ);

		/*sym_hash_enable(portid,RTE_ETH_FLOW_NONFRAG_IPV6_TCP,RTE_ETH_HASH_FUNCTION_TOEPLITZ);
		sym_hash_enable(portid,RTE_ETH_FLOW_NONFRAG_IPV6_UDP,RTE_ETH_HASH_FUNCTION_TOEPLITZ);
		sym_hash_enable(portid,RTE_ETH_FLOW_FRAG_IPV6,RTE_ETH_HASH_FUNCTION_TOEPLITZ);
		sym_hash_enable(portid, RTE_ETH_FLOW_NONFRAG_IPV6_SCTP,RTE_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ);
		sym_hash_enable(portid, RTE_ETH_FLOW_NONFRAG_IPV6_OTHER,RTE_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ);*/
		sym_hash_set(portid, 1);
		if(ret < 0){
			return ret;
		}
		/* get port_idt mac addr of NIC */
		struct rte_ether_addr addr;
		ret = rte_eth_macaddr_get(portid, &addr);
		if (ret < 0) {
			printf("Failed to get MAC address on port %u: %s\n",
			portid, rte_strerror(-ret));
			return ret;
		}
		printf("Port %u MAC: %02"PRIx8" %02"PRIx8" %02"PRIx8
				" %02"PRIx8" %02"PRIx8" %02"PRIx8"\n",
				(unsigned)portid,
				addr.addr_bytes[0], addr.addr_bytes[1],
				addr.addr_bytes[2], addr.addr_bytes[3],
				addr.addr_bytes[4], addr.addr_bytes[5]);
		ret = init_mem(portid,NB_MBUF(1));
		if(ret < 0)
			rte_exit(EXIT_FAILURE,"can't init mem\n");
		memset(&port_stat, 0, sizeof(port_stat));
		/* init one TX queue per couple (lcore,port) */
		queueid = 0;
		for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
			if (rte_lcore_is_enabled(lcore_id) == 0)
				continue;
			printf("txq=%u,%d,%d ", lcore_id, queueid, 0);
			fflush(stdout);

			txconf = &dev_info.default_txconf;
			txconf->offloads = local_port_conf.txmode.offloads;
			ret = rte_eth_tx_queue_setup(portid, queueid, nb_txd,
						     0, txconf);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
					"rte_eth_tx_queue_setup: err=%d, "
					"port=%d\n", ret, portid);

			qconf = &lcore_conf_arr[lcore_id];
			qconf->tx_queue_id[portid] = queueid;
			queueid++;

			qconf->tx_port_id[qconf->n_tx_port] = portid;
			qconf->n_tx_port++;
		}
		printf("\n");
	}

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		qconf = &lcore_conf_arr[lcore_id];
		printf("\nInitializing rx queues on lcore %u ... ", lcore_id );
		fflush(stdout);
		/* init RX queues */
		for(queue = 0; queue < qconf->n_rx_queue; ++queue) {
			struct rte_eth_rxconf rxq_conf;

			portid = qconf->rx_queue_list[queue].port_id;
			queueid = qconf->rx_queue_list[queue].queue_id;

			printf("rxq=%d,%d ", portid, queueid);
			fflush(stdout);

			ret = rte_eth_dev_info_get(portid, &dev_info);
			if (ret != 0)
				rte_exit(EXIT_FAILURE,
					"Error during getting device (port %u) info: %s\n",
					portid, strerror(-ret));

			rxq_conf = dev_info.default_rxconf;
			rxq_conf.offloads = port_conf.rxmode.offloads;
			ret = rte_eth_rx_queue_setup(portid, queueid,
					nb_rxd, 0,
					&rxq_conf,
					pktmbuf_pool[portid]);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
				"rte_eth_rx_queue_setup: err=%d, port=%d\n",
				ret, portid);
		}
	}
	return 0;
}
static int
init_lcore(void){
    uint16_t i, nb_rx_queue;
    uint8_t lcore;
    for (i = 0; i < nb_lcore_params; ++i) {
        lcore = lcore_map_arr_default[i].lcore_id;
        nb_rx_queue = lcore_conf_arr[lcore].n_rx_queue;
        if (nb_rx_queue >= MAX_RX_QUEUE_PER_LCORE) {
            printf("error: too many queues (%u) for lcore: %u\n",
                (unsigned)nb_rx_queue + 1, (unsigned)lcore);
            return -1;
        } else {
            lcore_conf_arr[lcore].rx_queue_list[nb_rx_queue].port_id =
                lcore_map_arr_default[i].port_id;
            lcore_conf_arr[lcore].rx_queue_list[nb_rx_queue].queue_id =
                lcore_map_arr_default[i].queue_id;
            lcore_conf_arr[lcore].n_rx_queue++;
        }
    }
    return 0;
}
static void
check_all_ports_link_status()
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint16_t portid;
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;
	int ret;

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		if (force_quit)
			return;
		all_ports_up = 1;
		RTE_ETH_FOREACH_DEV(portid) {
			if (force_quit)
				return;
			memset(&link, 0, sizeof(link));
			ret = rte_eth_link_get_nowait(portid, &link);
			if (ret < 0) {
				all_ports_up = 0;
				if (print_flag == 1)
					printf("Port %u link get failed: %s\n",
						portid, rte_strerror(-ret));
				continue;
			}

		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

//end of init section
//utility section
static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}
}
static void
print_stats(uint64_t tim)
{
	//debug propose
	uint64_t total_size, total_packets_rx;
	unsigned portid;
	float clk_rate = rte_get_timer_hz() * 1.0;
	total_size = 0;
	total_packets_rx = 0;
	const char clr[] = { 27, '[', '2', 'J', '\0' };
	const char topLeft[] = { 27, '[', '1', ';', '1', 'H','\0' };
	
		/* Clear screen and move to top left */
	printf("%s%s", clr, topLeft);

	printf("\t\ttime taken: %lf",tim/clk_rate);
	printf("\nPort statistics ====================================");

	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
		/* skip disabled ports */
		if(portid > n_port - 1){
			continue;
		}
		printf("\nStatistics for port %u ------------------------------"
			   "\nPackets received of this period: %20"PRIu64
			   "\nSize of this peroid (Mbits): %10"PRIu64,
			   portid,
			   port_stat[portid].rx_packet,
			   (port_stat[portid].size*8)/1000000
			   );

		total_size+= port_stat[portid].size;
		total_packets_rx += port_stat[portid].rx_packet;
		port_stat[portid].rx_packet = 0;
		port_stat[portid].size = 0;
	}
	printf("\nAggregate statistics ==============================="
		   "\nTotal packets received: %14"PRIu64
		   "\nTotal size(Mbits): %15"PRIu64,
		   total_packets_rx,
		   (total_size*8)/1000000);
	printf("\n\nThere are  %"PRIu64" IPv4 packets"
			"\nwhich has total usage of %"PRIu64" Mbits"
			"\n\t--> server %"PRIu64" packets"
			"\n\t--> client %"PRIu64" packets"
			"\n\nThere are %"PRIu64" IPv6 packets"
			"\n\t--> server %"PRIu64" packets"
			"\n\t--> client %"PRIu64" packets"
			"\nwhich has total usage of %"PRIu64" Mbits",
			data_info[!isAdded].n_ipv4_pack,(data_info[!isAdded].ipv4_usage*8)/1000000,data_info[!isAdded].server_pack_v4,data_info[!isAdded].client_pack_v4
			,data_info[!isAdded].n_ipv6_pack,data_info[!isAdded].server_pack_v6,data_info[!isAdded].client_pack_v6,(data_info[!isAdded].ipv6_usage*8)/1000000);
	
	printf("\n====================================================\n");
	printf("Time peroid%"PRIu64"\n",real_seconds);
	printf("printAll %d\n",printAll);
}

//rfc 1812 check all code copy from l3fwd.h
static int
is_valid_ipv4_pkt(struct rte_ipv4_hdr *pkt,uint32_t len)
{
	if(len < sizeof(struct rte_ipv4_hdr))
		return -1;
	if((pkt->version_ihl >> 4) != 4)
		return -3;
	if((pkt->version_ihl & 0xf)<5)
		return -4;
	if(rte_cpu_to_be_16(pkt->total_length) < sizeof(struct rte_ipv4_hdr))
		return -5;
	return 0;
}
//process section
static void
add_to_hash(uint32_t addr,uint16_t port1,uint16_t port2,uint64_t size,uint8_t l3_pro,uint32_t dst_addr,char *target,int setflag)
{
	//add data to my defined array
	struct compo_keyV4 tmp_key;
	char buff[255];
	int res,res2;
	tmp_key.dst_port = port2;
	tmp_key.src_port = port1; 
	tmp_key.l3_pro = l3_pro;
	tmp_key.ipv4_addr = addr;
	tmp_key.ipv4_addr_dst = dst_addr;
	if(target == "server_v4"){
		res = rte_hash_lookup(hash_tb[isAdded],(void *)&tmp_key);
		if(res < 0){
			if(res == -EINVAL){
				printf("Error\n");
			}
			if(res == -2){
				res2 = rte_hash_add_key(hash_tb[isAdded],(void *)&tmp_key);
				rte_atomic64_add(&ipv4_stat[res2][isAdded].size_of_this_p,size);
				rte_atomic64_add(&ipv4_stat[res2][isAdded].n_pkt,1);
				key_list[numkey[isAdded]][isAdded] = tmp_key;
				numkey[isAdded]++;
			}
		}
		else{
			rte_atomic64_add(&ipv4_stat[res][isAdded].size_of_this_p,size);
			rte_atomic64_add(&ipv4_stat[res][isAdded].n_pkt,1);
			if(l3_pro == 0x06)
			{
				if(tcp_port_lim[port1]>0 || tcp_port_lim[port2] > 0)
				{
					rte_atomic64_set(&ipv4_stat[res][isAdded].is_alert,1);
				}
			}
			if(l3_pro == 0x11){
				if(udp_port_lim[port1] > 0 || udp_port_lim[port2] > 0) rte_atomic64_set(&ipv4_stat[res][isAdded].is_alert,1);
			}
			if(setflag){
				rte_atomic64_set(&ipv4_stat[res][isAdded].is_alert,1);
			}
			if(printAll)
			{
				rte_atomic64_set(&ipv4_stat[res][isAdded].is_alert,1);
			}
		}		
	}
	else if(target == "client_v4"){
		res = rte_hash_lookup(hash_tb_cli[isAdded],(void *)&tmp_key);
		if(res < 0){
			if(res == -EINVAL){
				printf("Error\n");
			}
			if(res == -2){
				res2 = rte_hash_add_key(hash_tb_cli[isAdded],(void *)&tmp_key);
				if(res2 > 0){
					rte_atomic64_add(&ipv4_cli[res2][isAdded].size_of_this_p,size);
					rte_atomic64_add(&ipv4_cli[res2][isAdded].n_pkt,1);
					key_list_cli[numkey_cli[isAdded]][isAdded] = tmp_key;
					numkey_cli[isAdded]++;
				}
			}
		}
		else{
			rte_atomic64_add(&ipv4_cli[res][isAdded].size_of_this_p,size);
			rte_atomic64_add(&ipv4_cli[res][isAdded].n_pkt,1);
			if(l3_pro == 0x06)
			{
				if (tcp_port_lim[port1] >0 || tcp_port_lim[port2] > 0)
				{
					rte_atomic64_set(&ipv4_cli[res][isAdded].is_alert,1);
				}
			}
			if (l3_pro == 0x11)
			{
				if(udp_port_lim[port1] > 0 || udp_port_lim[port2] > 0) rte_atomic64_set(&ipv4_cli[res][isAdded].is_alert,1);
			}
			if(setflag){
				rte_atomic64_set(&ipv4_cli[res][isAdded].is_alert,1);
			}		
			if(printAll==1){//default case?
				rte_atomic64_set(&ipv4_cli[res][isAdded].is_alert,1);
			}
		}
	}
	memset(buff,0,sizeof(buff));
}
static void
process_data(struct rte_mbuf *data,unsigned portid){
	int res,res2;
	int collect = 0;
	struct rte_ether_hdr *l2_hdr;
	struct compo_keyV6 tmp_s;
	uint16_t eth_type;
	uint32_t src,dst;
	l2_hdr = rte_pktmbuf_mtod(data, struct rte_ether_hdr *);
	eth_type = rte_be_to_cpu_16(l2_hdr->ether_type);
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rte_udp_hdr *udp_data;
	struct rte_tcp_hdr  *tcp_data;
	uint16_t src_port = 0;
	uint16_t dst_port = 0;
	int indexV6;
	switch (eth_type)
	{
	case RTE_ETHER_TYPE_IPV4:
		ipv4_hdr = (struct rte_ipv4_hdr *)((char *)l2_hdr +(int)(sizeof(struct rte_ether_hdr)));
		src = ipv4_hdr->src_addr;
		dst = ipv4_hdr->dst_addr;
		if(is_valid_ipv4_pkt(ipv4_hdr,data->data_len) == 0){
			if(isVerbose){
				rte_atomic64_add(&data_info[isAdded].n_ipv4_pack,1);
				rte_atomic64_add(&data_info[isAdded].ipv4_usage,data->pkt_len);
			}
			switch (ipv4_hdr->next_proto_id)
			{
			case 0x11:
				udp_data = (struct rte_udp_hdr *)((char *)ipv4_hdr + sizeof(struct rte_ipv4_hdr));
				dst_port = rte_cpu_to_be_16(udp_data->dst_port);
				src_port = rte_cpu_to_be_16(udp_data->src_port);
				break;
			case 0x06:
				tcp_data = (struct rte_tcp_hdr *)((char *)ipv4_hdr + sizeof(struct rte_ipv4_hdr));
				dst_port = rte_cpu_to_be_16(tcp_data->dst_port);
				src_port = rte_cpu_to_be_16(tcp_data->src_port);
				break;
			default:
				src_port = 0;
				dst_port = 0;
				break;
			}
			//basic classification
			res = src%RECORD_ENTIRES;
			res2 = dst%RECORD_ENTIRES;
			if(host_lim[res].is_alert == 0 && host_lim[res].realaddr == src){
				//printf("%"PRIu32"\n",src);
				rte_atomic64_add(&host_stat[res][isAdded].size_of_this_p,data->pkt_len);
				rte_atomic64_add(&host_stat[res][isAdded].n_pkt,1);
				collect = 1;
			}
			if(host_lim[res2].is_alert == 0 && host_lim[res2].realaddr == dst){
				rte_atomic64_add(&host_stat[res][isAdded].size_of_this_p,data->pkt_len);
				rte_atomic64_add(&host_stat[res][isAdded].n_pkt,1);
				collect = 1;				
			}

 				if(src_port < 1024 && (ipv4_hdr->next_proto_id == 0x06 || ipv4_hdr->next_proto_id == 0x11)){
					rte_atomic64_add(&data_info[isAdded].server_pack_v4,1);
					rte_atomic64_add(&data_info[isAdded].client_pack_v4,1);
					add_to_hash(src,src_port,dst_port,data->pkt_len,ipv4_hdr->next_proto_id,dst,"server_v4",collect);
					add_to_hash(dst,dst_port,src_port,data->pkt_len,ipv4_hdr->next_proto_id,src,"client_v4",collect);
				}
				else if(src_port > 1024 && dst_port > 1024){
					rte_atomic64_add(&data_info[isAdded].client_pack_v4,1);
					add_to_hash(src,src_port,dst_port,data->pkt_len,ipv4_hdr->next_proto_id,dst,"client_v4",collect);
					add_to_hash(dst,dst_port,src_port,data->pkt_len,ipv4_hdr->next_proto_id,src,"client_v4",collect);
				}
				else if(src_port > 1024 && dst_port < 1024)
				{
					rte_atomic64_add(&data_info[isAdded].server_pack_v4,1);
					rte_atomic64_add(&data_info[isAdded].client_pack_v4,1);
					add_to_hash(src,src_port,dst_port,data->pkt_len,ipv4_hdr->next_proto_id,dst,"client_v4",collect);
					add_to_hash(dst,dst_port,src_port,data->pkt_len,ipv4_hdr->next_proto_id,src,"server_v4",collect);
				}
				else
				{
					rte_atomic64_add(&data_info[isAdded].server_pack_v4,1);
					add_to_hash(src,src_port,dst_port,data->pkt_len,ipv4_hdr->next_proto_id,dst,"server_v4",collect);
					add_to_hash(dst,dst_port,src_port,data->pkt_len,ipv4_hdr->next_proto_id,src,"server_v4",collect);
				}
			
			
		}
		break;
	case RTE_ETHER_TYPE_IPV6:
		ipv6_hdr = (struct rte_ipv6_hdr *)((char *)l2_hdr +(int)sizeof(struct rte_ether_hdr));
		if(isVerbose){
			rte_atomic64_add(&data_info[isAdded].n_ipv6_pack,1);
			rte_atomic64_add(&data_info[isAdded].ipv6_usage,data->pkt_len);			
		}
		switch (ipv6_hdr ->proto)
		{
			case 0x11:
				udp_data = (struct rte_udp_hdr *)((char *)ipv6_hdr + sizeof(struct rte_ipv6_hdr));
				dst_port = udp_data->dst_port;
				src_port = udp_data->src_port;
				break;
			case 0x06:
				tcp_data = (struct rte_tcp_hdr *)((char *)ipv6_hdr + sizeof(struct rte_ipv6_hdr));
				dst_port = tcp_data->dst_port;
				src_port = tcp_data->src_port;
				break;
			default:
				src_port = 0;
				dst_port = 0;
				break;
		}
		//check for server in both sides
 		if(src_port < 1024){
			rte_atomic64_add(&data_info[isAdded].server_pack_v6,1);
			for (size_t i = 0; i < 16; i++)
			{
				tmp_s.ipv6_addr[i] = ipv6_hdr->src_addr[i];
				tmp_s.ipv6_addr_dst[i] = ipv6_hdr->dst_addr[i];
			}
			tmp_s.l3_pro = ipv6_hdr->proto;
			tmp_s.src_port = src_port;
			tmp_s.dst_port = dst_port;
			//printf("%"PRIu8"\n",tmp_s.ipv6_addr[0]);
			if((void *)&tmp_s != NULL & tmp_s.ipv6_addr != NULL & tmp_s.ipv6_addr_dst != NULL){
				res = rte_hash_add_key(hash_tb_v6[isAdded],(void *)&tmp_s);
				if(res <0)
				{
					if(res == -EINVAL){
						printf("Invalid param?\n");
					}
					if(res == -ENOSPC){
						printf("No space?\n");
					}
				}
				indexV6 = rte_hash_count(hash_tb_v6[isAdded]) - 1;
				key_list6[indexV6][isAdded] = tmp_s;
				numkeyV6[isAdded] = indexV6;
				rte_atomic64_add(&ipv6_stat[res][isAdded].n_pkt,1);
				rte_atomic64_add(&ipv6_stat[res][isAdded].size_of_this_p,data->pkt_len);
			} 
		}
		else if(src_port >1024 || dst_port > 1024)
		{
			rte_atomic64_add(&data_info[isAdded].server_pack_v6,1);
		}
		break;
	default:
		break;
	}
	rte_atomic64_add(&port_stat[portid].size,data->pkt_len);
	rte_pktmbuf_free(data);
}
static void
main_loop(void)
{
	unsigned lcore_id,nb_rx;
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *m;
	int sent;
	struct lcore_conf *qconf;
	struct lcore_rx_queue *rx_que_ptr;
	uint64_t prev_tsc,diff_tsc,curr_tsc,timer_tsc;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S *
			BURST_TX_DRAIN_US;
	lcore_id = rte_lcore_id();
	qconf = &lcore_conf_arr[lcore_id];
	unsigned queid,j;
	unsigned portid;
	if(qconf ->n_rx_queue == 0){
		printf("lcore %u has nothing to do\n",lcore_id);
		return;
	}
	for (unsigned i = 0;i<qconf->n_rx_queue;i++){
		rx_que_ptr = &qconf->rx_queue_list[i];
		portid = rx_que_ptr->port_id;
		queid = rx_que_ptr->queue_id;
		printf("RX port for %u lcore is %u (Queue id is %u)\n",lcore_id,portid,queid);
	}
	for (unsigned i =0;i<qconf->n_tx_port;i++){
		printf("TX port for %u lcore is %u (Queue id is %u)\n",lcore_id,qconf->tx_port_id[i],qconf->tx_queue_id[i]);
	}
	printf("\n\n");
	prev_tsc = 0;
	timer_tsc = 0;
	struct rte_eth_dev_tx_buffer *buffer;
	while (!force_quit)
	{
		curr_tsc = rte_rdtsc();
		diff_tsc = curr_tsc - prev_tsc;
		/*if(unlikely(diff_tsc > drain_tsc)){
			for(unsigned i = 0;i<qconf->n_tx_port;i++){
				portid = qconf->tx_port_id[i];
				buffer = tx_buffer[portid][qconf->tx_queue_id[i]];
				sent = rte_eth_tx_buffer_flush(portid,qconf->tx_queue_id[i],buffer);
			}
		}*/
		timer_tsc += diff_tsc;
		if(unlikely(timer_tsc >= time_peroid)){
			/* do this only on master core */
			if (lcore_id == rte_get_master_lcore()) {
				isAdded = !isAdded;
				if(isVerbose){
					print_stats(timer_tsc);
				}
				//printf("%d\n",elem_lim);
				for (int i = 0; i < elem_lim; i++)
				{
					lim_addr[i];
					int res = lim_addr[i]%RECORD_ENTIRES;
					//printf("%d\n",res);
					if(host_lim[res].is_alert == 0)
					{
						if (host_lim[res].size_of_this_p < host_stat[res][!isAdded].size_of_this_p*8)
						{
							float usage = (float)(host_stat[res][!isAdded].size_of_this_p*8)/(float)(10*10*10*10*10*10*real_seconds);
							uint64_t real_lim = (host_lim[res].size_of_this_p)/(10*10*10*10*10*10*real_seconds);
							syslog(LOG_WARNING,"%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8" has exceeded limit %"PRIu64"Mb/s (%f Mb/s for real use)",(lim_addr[i]&0xff)
									,((lim_addr[i]>>8)&0xff),((lim_addr[i]>>16)&0xff),(lim_addr[i]>>24)&0xff,real_lim,usage);
						}
						host_stat[res][!isAdded].size_of_this_p=0;
						host_stat[res][!isAdded].n_pkt=0;
					}
					
				}
				
				write_log_v4(hash_tb[!isAdded],"server",!isAdded);
				write_log_v4(hash_tb_cli[!isAdded],"client",!isAdded);
				write_log_v6(hash_tb_v6[!isAdded],"server",!isAdded);
				numkey[!isAdded]=0;
				numkey_cli[!isAdded]=0;
				numkeyV6[!isAdded]=0;
				if(isVerbose){
					data_info[!isAdded].ipv4_usage = 0;
					data_info[!isAdded].server_pack_v4=0;
					data_info[!isAdded].client_pack_v4=0;
					data_info[!isAdded].n_ipv4_pack = 0;
					data_info[!isAdded].n_ipv6_pack = 0;
					data_info[!isAdded].server_pack_v6=0;
					data_info[!isAdded].client_pack_v6=0;
					data_info[!isAdded].ipv6_usage = 0;
				}
				//numkeyV6[!isAdded] = 0;

				rte_hash_reset(hash_tb[!isAdded]);
				rte_hash_reset(hash_tb_cli[!isAdded]);
				rte_hash_reset(hash_tb_v6[!isAdded]);
				/* reset the timer */
				timer_tsc = 0;
			}
		}
		prev_tsc = curr_tsc;
		//process rx queue
		for(unsigned i = 0; i < qconf -> n_rx_queue;i++){
			rx_que_ptr = &qconf->rx_queue_list[i];
			portid = rx_que_ptr->port_id;
			queid = rx_que_ptr->queue_id;
			nb_rx = rte_eth_rx_burst(portid,queid,pkts_burst,MAX_PKT_BURST);
			if(unlikely(nb_rx == 0)){
				continue;
			}
			rte_atomic64_add(&port_stat[portid].rx_packet,nb_rx);
			for(unsigned j = 0;j<nb_rx;j++){
				m = pkts_burst[j];
				rte_prefetch0(rte_pktmbuf_mtod(m, void *));
				process_data(pkts_burst[j],portid);
				//forward_data(pkts_burst[j],!qconf->tx_port_id[i],qconf->tx_queue_id[i]);
			}
		}
	}
	

}
static int
myapp_launch_one_lcore(__rte_unused void *dummy){
	main_loop();
	return 0;
}
int
main(int argc, char **argv){
	int ret;
	unsigned nb_ports;
	unsigned lcore_id;
	uint16_t portid;
	/*init EAL param*/
	ret = rte_eal_init(argc,argv);
	if(ret < 0)
		rte_exit(EXIT_FAILURE,"Invalid EAL params\n");
	argc -= ret;
	argv += ret;
	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	//ret = parse_args(argc,argv);
	ret = init_host_lim();
	if(ret < 0)
		rte_exit(EXIT_FAILURE,"Invalid APP params\n");
	printf("timer: %"PRIu64" CPU cycle: %"PRIu64"\n",time_peroid,rte_get_timer_hz());
	real_seconds = time_peroid;
	time_peroid *= rte_get_timer_hz();
	nb_ports = rte_eth_dev_count_avail();
	n_port = nb_ports;
	if(nb_ports == 0)
		rte_exit(EXIT_FAILURE,"No port available!!!\n");
	ret = init_lcore();
	if(ret != 0)
		rte_exit(EXIT_FAILURE,"can't init queue\n");
	ret = init_port();
	if(ret != 0)
		rte_exit(EXIT_FAILURE,"can't init ports\n");
	/* start ports */
	printf("\n");
	RTE_ETH_FOREACH_DEV(portid) {
		/* Start device */
		printf("Starting port: %"PRIu16"..... ",portid);
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				"rte_eth_dev_start: err=%d, port=%d\n",
				ret, portid);

		/*
		 * If enabled, put device in promiscuous mode.
		 * This allows IO forwarding mode to forward packets
		 * to itself through 2 cross-connected  ports of the
		 * target machine.
		 */
		ret = rte_eth_promiscuous_enable(portid);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				"rte_eth_promiscuous_enable: err=%s, port=%u\n",
				rte_strerror(-ret), portid);
		printf("Done\n");
	}
	//init hash table for server roles
	for (int i = 0; i < 2; i++)
	{
		char name[255];
		sprintf(name,"ipv4_hash%d",i);
		struct rte_hash_parameters params = {
			.name = name,
			.entries = RECORD_ENTIRES,
			.key_len = sizeof(struct compo_keyV4),
			.hash_func = rte_jhash,
			.hash_func_init_val = 0,
			.socket_id = 0,
		};
		hash_tb[i] = rte_hash_create(&params);
		if(!hash_tb[i]){
			fprintf(stderr,"create hash%d failed\n",i);
			return -1;
		}
	}
	//end of initialization of server roles
	//client roles
	for (int i = 0; i < 2; i++)
	{
		char name[255];
		sprintf(name,"client hash%d",i);
		struct rte_hash_parameters params = {
			.name = name,
			.entries = RECORD_ENTIRES,
			.key_len = sizeof(struct compo_keyV4),
			.hash_func = rte_jhash,
			.hash_func_init_val = 0,
			.socket_id = 0,
		};
		hash_tb_cli[i] = rte_hash_create(&params);
		if(!hash_tb_cli[i]){
			fprintf(stderr,"create cleint%d failed\n",i);
			return -1;
		}
	}
	//init hash table for server ipv6 roles
	for (int i = 0; i < 2; i++)
	{
		char name[255];
		sprintf(name,"ipv6 hash%d",i);
		struct rte_hash_parameters params = {
			.name = name,
			.entries = RECORD_ENTIRES,
			.key_len = sizeof(struct compo_keyV6),
			.hash_func = rte_jhash,
			.hash_func_init_val = 0,
			.socket_id = 0,
		};
		hash_tb_v6[i] = rte_hash_create(&params);
		if(!hash_tb_v6[i]){
			fprintf(stderr,"create ipv6%d failed\n",i);
			return -1;
		}
	}
	//end of initialization of server roles
	
	check_all_ports_link_status();
	//printf("Please enter usage limit: ");
	//scanf("%"PRIu64,&global_limit);
	openlog("TEST IDS LOG JA",LOG_PID,LOG_USER);
	syslog(LOG_INFO,"Starting C process (Alert system,Packet processor,Data manager)");
	ret = 0;
	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(myapp_launch_one_lcore, NULL, CALL_MASTER);
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}
	RTE_ETH_FOREACH_DEV(portid) {
		printf("Closing port %d...", portid);
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}
	for (int i = 0; i < 2; i++)
	{
		/* code */
		rte_hash_free(hash_tb[i]);
		rte_hash_free(hash_tb_cli[i]);
		rte_hash_free(hash_tb_v6[i]);
	}
	syslog(LOG_INFO,"Closing packet processor/data manager C process......");
	closelog();
	printf("Bye...\n");
}
