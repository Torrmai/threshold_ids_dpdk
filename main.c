/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */
#include <time.h>
#include <signal.h>
#include <stdint.h>
#include <inttypes.h>
#include <getopt.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_hash.h>
#include <rte_jhash.h>


#define RX_RING_SIZE 4096
#define TX_RING_SIZE 4096

#define NUM_MBUFS 16382
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define RECORD_ENTIRES 1000000

static const char usage[] =
	"%s EAL_ARGS -- [-t]\n";

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
	},
};

static struct {
	uint64_t total_cycles;
	uint64_t total_queue_cycles;
	uint64_t total_pkts;
} latency_numbers;
static struct statistic_ja
{
	uint32_t IPv4_addr;
	uint64_t total_size;
	uint32_t start_time;
};
static struct sample_flied
{
	char ip_addr[100];
	uint64_t total_size;
	uint32_t start_time;
	uint32_t detect_time;
};
static struct log_pref_data
{
	uint64_t packet_per_cycle;
	uint64_t total_size;
	uint64_t total_pkt;
	uint32_t time_stamp;
	uint32_t err_num;
	uint32_t suc_num;
};
int hw_timestamping;
uint64_t tot_size = 0;
clock_t st_time,ts;
time_t ti;
uint32_t index_of_file = 0;
uint32_t sample_log_i = 0;
struct tm currtime;
struct rte_hash *hash_tb;
struct rte_hash_parameters params;
static struct statistic_ja ipv4_stat[RECORD_ENTIRES];//store data?
static struct log_pref_data log_col[100000];//change to write to mem
static struct sample_flied log_print[1000000];
FILE *fp;
uint32_t count_err=0;
uint32_t count_suc=0;

#define TICKS_PER_CYCLE_SHIFT 16
static uint64_t ticks_per_cycle_mult;
void initHandler(int);
void
initHandler(int sig){
	char c;
	//char *sErrMsg = 0;
	signal(sig, SIG_IGN);
	printf("Are you sure to quit? [y/N] ");
	c = getchar();
	if (c == 'y' || c == 'Y')
	{
		for (int i = 0; i < index_of_file; i++)
		{
			fprintf(fp,"%"PRIu64",%"PRIu64",%d,%"PRIu32",%"PRIu32",%"PRIu32"\n",
					log_col[i].packet_per_cycle,log_col[i].total_size,log_col[i].total_pkt,log_col[i].time_stamp
					,log_col[i].err_num,log_col[i].suc_num);
		}
		
		fclose(fp);
		exit(0);
	}
	else
		signal(SIGINT,initHandler);
	
}

static uint16_t
add_timestamps(uint16_t port __rte_unused, uint16_t qidx __rte_unused,
		struct rte_mbuf **pkts, uint16_t nb_pkts,
		uint16_t max_pkts __rte_unused, void *_ __rte_unused)
{
	unsigned i;
	uint64_t now = rte_rdtsc(); 
	for (i = 0; i < nb_pkts; i++)
		pkts[i]->udata64 = now;
 ;
	return nb_pkts;
}

static uint16_t
calc_latency(uint16_t port, uint16_t qidx __rte_unused,
		struct rte_mbuf **pkts, uint16_t nb_pkts, void *_ __rte_unused)
{
	/*ti = time(NULL);
	currtime = *localtime(&ti);*/
	ts = clock();
	uint64_t cycles = 0;
	uint64_t queue_ticks = 0;
	uint16_t eth_type;
	uint64_t now = rte_rdtsc();
	uint32_t ticks;
	uint32_t src,dst;
	uint32_t tmpsize;
	unsigned i;
	int32_t res;
	int32_t res2;
	struct rte_ether_hdr *ether_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	int l2_len = sizeof(struct rte_ether_hdr);
	if (hw_timestamping)
		rte_eth_read_clock(port, &ticks);

	for (i = 0; i < nb_pkts; i++) {
		tmpsize = pkts[i]->pkt_len;
		cycles += now - pkts[i]->udata64;
		tot_size += tmpsize;
		ether_hdr = rte_pktmbuf_mtod(pkts[i], struct rte_ether_hdr *);
		eth_type = rte_be_to_cpu_16(ether_hdr->ether_type);
		switch (eth_type)
		{
		case RTE_ETHER_TYPE_IPV4:
			ipv4_hdr = (struct rte_ipv4_hdr *)((char *)ether_hdr + l2_len);
			src = ipv4_hdr->src_addr;
			dst = ipv4_hdr->dst_addr;
			//insert_data(db,src,pkts[i]->pkt_len);
			//res = rte_hash_add_key(hash_tb,(void*)&src);
			//printf("%"PRId32"\n",res);
			res = rte_hash_lookup(hash_tb,(void *)&src);
			if(res<0){
				if(res == -EINVAL){
					count_err++;
				}
				if(res == -ENOENT){
					res2 = rte_hash_add_key(hash_tb,(void *)&src);
				}
			}
			else{
				count_suc++;
				ipv4_stat[res].IPv4_addr = src;
				if(ipv4_stat[res].total_size > 235095650){
					if((uint32_t)time(NULL) - ipv4_stat[res].start_time < 16){
							sprintf(log_print[sample_log_i].ip_addr,"%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"",
							(uint8_t)(src & 0xff),
							(uint8_t)((src >> 8)&0xff),
							(uint8_t)((src>>16)&0xff),
							(uint8_t)((src>>24)&0xff));
							log_print[sample_log_i].total_size = ipv4_stat[res].total_size;
							log_print[sample_log_i].start_time = ipv4_stat[res].start_time;
							log_print[sample_log_i].detect_time = (uint32_t)time(NULL);
							sample_log_i++;
					}
					ipv4_stat[res].total_size = 0;
					ipv4_stat[res].start_time = 0;
				}
				ipv4_stat[res].total_size += tmpsize;
				if(ipv4_stat[res].start_time == 0){
					ipv4_stat[res].start_time = (uint32_t)time(NULL);
				}
				
			}
			break;
		default:
			break;
		}
	}

	latency_numbers.total_cycles += cycles;

	latency_numbers.total_pkts += nb_pkts;

	if (latency_numbers.total_pkts > (100 * 1000* 1000ULL)) {
		/*fprintf(fp,"%"PRIu64",%"PRIu64",%d,%.2f,%"PRIu32",%"PRIu32"\n",
		latency_numbers.total_cycles / latency_numbers.total_pkts,tot_size,latency_numbers.total_pkts,(double)(ts-st_time)/CLOCKS_PER_SEC,count_err,count_suc);*/
		log_col[index_of_file].packet_per_cycle = latency_numbers.total_cycles / latency_numbers.total_pkts;
		log_col[index_of_file].total_size = tot_size;
		log_col[index_of_file].total_pkt = latency_numbers.total_pkts;
		log_col[index_of_file].time_stamp = (uint32_t)time(NULL);
		log_col[index_of_file].err_num = count_err;
		log_col[index_of_file].suc_num = count_suc;
		//printf("%"PRIu64",%d\n",log_col[index_of_file].total_size,index_of_file);
		index_of_file++;
		printf("number of alert -> %"PRIu32"\n",sample_log_i);
		//printf("%"PRIu32", %"PRIu64"\n",ipv4_stat[0].IPv4_addr,ipv4_stat[0].total_size);
		latency_numbers.total_cycles = 0;
		latency_numbers.total_queue_cycles = 0;
		latency_numbers.total_pkts = 0;
		tot_size = 0;
		count_err = 0;
		count_suc = 0;
	}
	return nb_pkts;
}

/*
 * Initialises a given port using global settings and with the rx buffers
 * coming from the mbuf_pool passed as parameter
 */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rxconf rxconf;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));

		return retval;
	}

	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			DEV_TX_OFFLOAD_MBUF_FAST_FREE;

	if (hw_timestamping) {
		if (!(dev_info.rx_offload_capa & DEV_RX_OFFLOAD_TIMESTAMP)) {
			printf("\nERROR: Port %u does not support hardware timestamping\n"
					, port);
			return -1;
		}
		port_conf.rxmode.offloads |= DEV_RX_OFFLOAD_TIMESTAMP;
	}

	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	rxconf = dev_info.default_rxconf;

	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
			rte_eth_dev_socket_id(port), &rxconf, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	retval  = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	if (hw_timestamping && ticks_per_cycle_mult  == 0) {
		uint64_t cycles_base = rte_rdtsc();
		uint64_t ticks_base;
		retval = rte_eth_read_clock(port, &ticks_base);
		if (retval != 0)
			return retval;
		rte_delay_ms(100);
		uint64_t cycles = rte_rdtsc();
		uint64_t ticks;
		rte_eth_read_clock(port, &ticks);
		uint64_t c_freq = cycles - cycles_base;
		uint64_t t_freq = ticks - ticks_base;
		double freq_mult = (double)c_freq / t_freq;
		printf("TSC Freq ~= %" PRIu64
				"\nHW Freq ~= %" PRIu64
				"\nRatio : %f\n",
				c_freq * 10, t_freq * 10, freq_mult);
		/* TSC will be faster than internal ticks so freq_mult is > 0
		 * We convert the multiplication to an integer shift & mult
		 */
		ticks_per_cycle_mult = (1 << TICKS_PER_CYCLE_SHIFT) / freq_mult;
	}

	struct rte_ether_addr addr;

	retval = rte_eth_macaddr_get(port, &addr);
	if (retval < 0) {
		printf("Failed to get MAC address on port %u: %s\n",
			port, rte_strerror(-retval));
		return retval;
	}
	printf("Port %u MAC: %02"PRIx8" %02"PRIx8" %02"PRIx8
			" %02"PRIx8" %02"PRIx8" %02"PRIx8"\n",
			(unsigned)port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	retval = rte_eth_promiscuous_enable(port);
	if (retval != 0)
		return retval;

	rte_eth_add_rx_callback(port, 0, add_timestamps, NULL);
	rte_eth_add_tx_callback(port, 0, calc_latency, NULL);

	return 0;
}

/*
 * Main thread that does the work, reading from INPUT_PORT
 * and writing to OUTPUT_PORT
 */
static  __rte_noreturn void
lcore_main(void)
{
	uint16_t port;

	RTE_ETH_FOREACH_DEV(port)
		if (rte_eth_dev_socket_id(port) > 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id());
	for (;;) {
		RTE_ETH_FOREACH_DEV(port) {
			struct rte_mbuf *bufs[BURST_SIZE];
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
					bufs, BURST_SIZE);
			if (unlikely(nb_rx == 0))
				continue;
			const uint16_t nb_tx = rte_eth_tx_burst(port ^ 1, 0,
					bufs, nb_rx);
			if (unlikely(nb_tx < nb_rx)) {
				uint16_t buf;

				for (buf = nb_tx; buf < nb_rx; buf++)
					rte_pktmbuf_free(bufs[buf]);
			}
		}
	}
}

/* Main function, does initialisation and calls the per-lcore functions */
int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	uint16_t nb_ports;
	uint16_t portid;
	int stat_db;
	struct option lgopts[] = {
		{ NULL,  0, 0, 0 }
	};
	int opt, option_index;


	/* init EAL */
	int ret = rte_eal_init(argc, argv);

	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	argc -= ret;
	argv += ret;

	while ((opt = getopt_long(argc, argv, "t", lgopts, &option_index))
			!= EOF)
		switch (opt) {
		case 't':
			hw_timestamping = 1;
			break;
		default:
			printf(usage, argv[0]);
			return -1;
		}
	optind = 1; /* reset getopt lib */

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports < 2 || (nb_ports & 1))
		rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
		NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
		RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* initialize all ports */
	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8"\n",
					portid);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too much enabled lcores - "
			"App uses only 1 lcore\n");

	/* call lcore_main on master core only */
	fp = fopen("tmp/add_hash_perf8.csv","w");
	//init table
	bzero(&params,sizeof(params));
	params.name = "";
	params.entries = RECORD_ENTIRES;
	params.key_len = sizeof (uint32_t);
	params.hash_func = rte_jhash;
	params.hash_func_init_val = 0;
	hash_tb = rte_hash_create (&params);
	if (!hash_tb) {
    	fprintf (stderr,"rte_hash_create failed\n");
    	return 1;
	}  
	printf("******************latency recorded in cpu cycle unit****************\n");
	fprintf(fp,"packet_per_cycle,total size,packet,time_stamp,err_count,success_count\n");
	st_time = clock();
	signal(SIGINT,initHandler);
	lcore_main();
	return 0;
}
