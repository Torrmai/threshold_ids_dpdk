#include <time.h>
#include <sys/time.h>
#include <signal.h>
#include <stdint.h>
#include <inttypes.h>
#include <getopt.h>
#include <stdbool.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_eth_ctrl.h>

#include "data_structure.h"
#define RECORD_ENTIRES 1000000
#define MAX_RX_QUEUE_PER_LCORE 1024
#define MEMPOOL_CACHE_SIZE 256
#define NB_MBUF(nports) RTE_MAX(	\
	(nports*nb_rx_queue*nb_rxd +		\
	nports*nb_lcores*64 +	\
	nports*3*nb_txd +		\
	nb_lcores*MEMPOOL_CACHE_SIZE),		\
	(unsigned)8192)
#define MAX_PKT_BURST 128
#define PREFETCH_OFFSET	3
static uint16_t nb_rxd = 128;
static uint16_t nb_txd = 512;
static uint64_t time_peroid = 10;
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
	uint16_t tx_queue_id[RTE_MAX_ETHPORTS];
}__rte_cache_aligned;
static struct lcore_conf lcore_conf_arr[RTE_MAX_LCORE];
#define RSS_HASH_KEY_LENGTH 40
static uint8_t hash_key[RSS_HASH_KEY_LENGTH] = {
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
};
static struct rte_eth_conf port_conf = {
    .rxmode = {
        .mq_mode = ETH_MQ_RX_RSS,
        .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
        .split_hdr_size = 0,
        .offloads = DEV_RX_OFFLOAD_RSS_HASH,
    },
    .rx_adv_conf = {
        .rss_conf = {
			.rss_key = hash_key,
        	.rss_key_len = RSS_HASH_KEY_LENGTH,
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
//statistical related data type
struct basic_port_statistic{
	uint64_t rx_packet;
	uint64_t size;
}__rte_cache_aligned;
struct basic_port_statistic port_stat[RTE_MAX_ETHPORTS];
struct usage_stat{
	uint64_t n_pkt;
	uint64_t size_of_this_p;
};
struct max_mem{
	uint32_t ipv4_addr;
	uint64_t n_pkt;
	uint64_t size_of_this_p;
};
static struct usage_stat ipv4_stat[RECORD_ENTIRES];
static struct max_mem max_stat[3];
struct rte_hash *hash_tb;
struct rte_hash_parameters params;
unsigned n_port;
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
}static void
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
		   "\nTotal size(Mbit): %15"PRIu64,
		   total_packets_rx,
		   (total_size*8)/1000000);
	for (int i = 0; i < 3; i++)
	{
		printf("\nCandidate #%d %"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8" With size of %"PRIu64" (Mbit)",
		i+1,
		(uint8_t)(max_stat[i].ipv4_addr & 0xff),
		(uint8_t)((max_stat[i].ipv4_addr >> 8)&0xff),
		(uint8_t)((max_stat[i].ipv4_addr >> 16)&0xff),
		(uint8_t)((max_stat[i].ipv4_addr >> 24)&0xff),
		(max_stat[i].size_of_this_p*8)/1000000);
	}
	
	printf("\n====================================================\n");
	for (int i = 0; i < 3; i++)
	{
		max_stat[i].size_of_this_p = 0;
		max_stat[i].n_pkt = 0;
	}
	isAdded = 0;
	rte_hash_reset(hash_tb);
	isAdded = 1;
}
//process section
static void
process_data(struct rte_mbuf *data,unsigned portid,entry_v4 *it){
	int res,res2;
	struct rte_ether_hdr *l2_hdr;
	uint16_t eth_type;
	uint32_t src,dst;
	l2_hdr = rte_pktmbuf_mtod(data, struct rte_ether_hdr *);
	eth_type = rte_be_to_cpu_16(l2_hdr->ether_type);
	struct rte_ipv4_hdr *ipv4_hdr;
	switch (eth_type)
	{
	case RTE_ETHER_TYPE_IPV4:
		ipv4_hdr = (struct rte_ipv4_hdr *)((char *)l2_hdr +(int)(sizeof(struct rte_ether_hdr)));
		src = ipv4_hdr->src_addr;
		dst = ipv4_hdr->dst_addr;
		if(isAdded == 1){
			res = rte_hash_lookup(hash_tb,(void *)&src);
			//printf("%d\n",res);
			if(res < 0){
				if(res == -EINVAL){
					printf("Error\n");
				}
				if(res == -2){
					res2 = rte_hash_add_key(hash_tb,(void *)&src);
				}
			}
			else{
				rte_atomic64_add(&ipv4_stat[res].size_of_this_p,data->pkt_len);
				rte_atomic64_add(&ipv4_stat[res].n_pkt,1);
				if(ipv4_stat[res].size_of_this_p > max_stat[0].size_of_this_p){
					max_stat[0].ipv4_addr = src;
					max_stat[0].size_of_this_p = ipv4_stat[res].size_of_this_p;
					max_stat[0].n_pkt = ipv4_stat[res].n_pkt;
				}
				else if(ipv4_stat[res].size_of_this_p < max_stat[0].size_of_this_p && ipv4_stat[res].size_of_this_p > max_stat[1].size_of_this_p){
					max_stat[1].ipv4_addr = src;
					max_stat[1].size_of_this_p = ipv4_stat[res].size_of_this_p;
					max_stat[1].n_pkt = ipv4_stat[res].n_pkt;
				}
				else if(ipv4_stat[res].size_of_this_p < max_stat[1].size_of_this_p && ipv4_stat[res].size_of_this_p > max_stat[2].size_of_this_p){
					max_stat[2].ipv4_addr = src;
					max_stat[2].size_of_this_p = ipv4_stat[res].size_of_this_p;
					max_stat[2].n_pkt = ipv4_stat[res].n_pkt;
				}
			}
		}
		else{
			//printf("%d\n",isAdded);
			add_tmp_v4(src,data->pkt_len,&it);
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
	struct lcore_conf *qconf;
	struct lcore_rx_queue *rx_que_ptr;
	uint64_t prev_tsc,diff_tsc,curr_tsc,timer_tsc;
	lcore_id = rte_lcore_id();
	qconf = &lcore_conf_arr[lcore_id];
	unsigned queid,j;
	unsigned portid;
	entry_v4 elem;
	TAILQ_INIT(&elem.head);
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
	while (!force_quit)
	{
		curr_tsc = rte_rdtsc();
		//process rx queue
		diff_tsc = curr_tsc - prev_tsc;
		for(unsigned i = 0; i < qconf -> n_rx_queue;i++){
			rx_que_ptr = &qconf->rx_queue_list[i];
			portid = rx_que_ptr->port_id;
			queid = rx_que_ptr->queue_id;
			nb_rx = rte_eth_rx_burst(portid,queid,pkts_burst,MAX_PKT_BURST);
			if(unlikely(nb_rx == 0)){
				//usleep(10);
				continue;
			}
			rte_atomic64_add(&port_stat[portid].rx_packet,nb_rx);
			for(unsigned j = 0;j<nb_rx;j++){
				m = pkts_burst[j];
				rte_prefetch0(rte_pktmbuf_mtod(m, void *));
				process_data(pkts_burst[j],portid,&elem);
			}
		}
/* 			for (; j < nb_rx; j++)
				rte_atomic64_add(&port_stat[portid].size,pkts_burst[j]->pkt_len);
				rte_pktmbuf_free(pkts_burst[j]); */
		prev_tsc = curr_tsc;
		timer_tsc += diff_tsc;
		if(unlikely(timer_tsc >= time_peroid)){
			/* do this only on master core */
			if (lcore_id == rte_get_master_lcore()) {
				print_stats(timer_tsc);
				/* reset the timer */
				timer_tsc = 0;
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
	time_peroid *= rte_get_timer_hz();
	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	//printf("timer: %"PRIu64" CPU cycle: %"PRIu64"\n",time_peroid,rte_get_timer_hz());
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
	bzero(&params,sizeof(params));
	params.name = "ipv4_hash";
	params.entries = RECORD_ENTIRES;
	params.key_len = sizeof(uint32_t);
	params.hash_func = rte_jhash;
	params.hash_func_init_val = 0;
	hash_tb = rte_hash_create(&params);
	if(!hash_tb){
		fprintf(stderr,"create hash failed\n");
		return 1;
	}
	check_all_ports_link_status();
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
	rte_hash_free(hash_tb);
	printf("Bye...\n");
}