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

#define MAX_RX_QUEUE_PER_LCORE 1024
#define MEMPOOL_CACHE_SIZE 256
#define NB_MBUF(nports) RTE_MAX(	\
	(nports*nb_rx_queue*nb_rxd +		\
	nports*nb_lcores*64 +	\
	nports*3*nb_txd +		\
	nb_lcores*MEMPOOL_CACHE_SIZE),		\
	(unsigned)8192)
#define MAX_PKT_BURST 64
#define PREFETCH_OFFSET	3
static uint16_t nb_rxd = 1024;
static uint16_t nb_txd = 1024;
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
unsigned n_port;
// init section
int
init_mem(uint16_t portid, unsigned int nb_mbuf)
{
	struct lcore_conf *qconf;
	int socketid;
	unsigned lcore_id;
	char s[64];

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		if (pktmbuf_pool[portid]== NULL) {
			snprintf(s, sizeof(s), "mbuf_pool_%d:%d",
				 portid, socketid);
			pktmbuf_pool[portid] =
				rte_pktmbuf_pool_create(s, nb_mbuf,
					MEMPOOL_CACHE_SIZE, 0,
					RTE_MBUF_DEFAULT_BUF_SIZE, socketid);
			if (pktmbuf_pool[portid] == NULL)
				rte_exit(EXIT_FAILURE,
					"Cannot init mbuf pool on  %d\n",
					socketid);
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

			printf("rxq=%d,%d,%d ", portid, queueid, 0);
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
			   "\nSize of this peroid: %21"PRIu64,
			   portid,
			   port_stat[portid].rx_packet,
			   port_stat[portid].size
			   );

		total_size+= port_stat[portid].size;
		total_packets_rx += port_stat[portid].rx_packet;
		port_stat[portid].rx_packet = 0;
		port_stat[portid].size = 0;
	}
	printf("\nAggregate statistics ==============================="
		   "\nTotal packets received: %14"PRIu64
		   "\nTotal size: %15"PRIu64,
		   total_packets_rx,
		   total_size);
	printf("\n====================================================\n");
}
//process section
static void
main_loop(void)
{
	unsigned lcore_id,nb_rx;
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct lcore_conf *qconf;
	struct lcore_rx_queue *rx_que_ptr;
	uint64_t prev_tsc,diff_tsc,curr_tsc,timer_tsc;
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
		printf("RX port for %u lcore is %u (Que id is %u)\n",lcore_id,portid,queid);
	}
	printf("\n\n");
	//printf("Starting to listen..................\n");
	prev_tsc = 0;
	timer_tsc = 0;
	while (!force_quit)
	{
		curr_tsc = rte_rdtsc();
		//process rx queue
		diff_tsc = curr_tsc - prev_tsc;
		for(unsigned i = 0; i < qconf -> n_rx_queue;i++){
			portid = qconf->rx_queue_list[i].port_id;
			queid = qconf->rx_queue_list[i].queue_id;
			nb_rx = rte_eth_rx_burst(portid,queid,pkts_burst,MAX_PKT_BURST);
			if(unlikely(nb_rx == 0)){
				//printf("%u lcore has no incoming packet\n",lcore_id);
				//usleep(2); debug goodies :)
				continue;
			}
			rte_atomic64_add(&port_stat[portid].rx_packet,nb_rx);
			for(j = 0;j<nb_rx;j++){
				rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j],void *));
				rte_atomic64_add(&port_stat[portid].size,pkts_burst[j]->pkt_len);
				rte_pktmbuf_free(pkts_burst[j]);
			}
		}
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
	printf("Bye...\n");
}