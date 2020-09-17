/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */
/* This file is developing.
 * It has nothing to do with main program for now
*/
#include <time.h>
#include <sys/time.h>
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

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define RECORD_ENTIRES 1000000

static const char usage[] =
	"%s EAL_ARGS -- [-t]\n";

#define RSS_HASH_KEY_LENGTH 40
static uint8_t hash_key[RSS_HASH_KEY_LENGTH] = {
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
};

struct rte_eth_conf port_conf = {
  .rxmode = {
    .mq_mode = ETH_MQ_RX_RSS,
  },
  .rx_adv_conf = {
    .rss_conf = {
        .rss_key = hash_key,
        .rss_key_len = RSS_HASH_KEY_LENGTH,
    }
   },
};


#define TICKS_PER_CYCLE_SHIFT 16
static int
lcore_job(__rte_unused void *arg)
{
	uint16_t port;
        uint64_t size_each_lcore = 0;
        double unix_epoch;
        unsigned lcore_id;
        lcore_id = rte_lcore_id();
        clock_t start,stop;
        printf("listening from core %u\n", lcore_id);
	RTE_ETH_FOREACH_DEV(port)
		if (rte_eth_dev_socket_id(port) > 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	printf("Core %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id());
        start = clock();
	for (;;) {
		RTE_ETH_FOREACH_DEV(port) {
			struct rte_mbuf *bufs[BURST_SIZE];
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
					bufs, BURST_SIZE);
			if (unlikely(nb_rx == 0))
				continue;
                        for(int i =0;i<nb_rx;i++){
                                size_each_lcore += bufs[i]->pkt_len;
                        }
                        stop = clock();
                        unix_epoch = (double)(stop-start)/CLOCKS_PER_SEC;
                        if(fmod(unix_epoch,2) == 0){
                                printf("Throuput: %"PRIu64" @ lcore: %u \n",size_each_lcore,lcore_id);
                                size_each_lcore = 0;
                        }
			const uint16_t nb_tx = rte_eth_tx_burst(port ^ 1, 0,
					bufs, nb_rx);
			if (unlikely(nb_tx < nb_rx)) {
				uint16_t buf;

				for (buf = nb_tx; buf < nb_rx; buf++)
					rte_pktmbuf_free(bufs[buf]);
			}
		}
	}
        return 0;
}
//set up function
int
port_init(uint16_t port,struct rte_mempool *mbuf_pool){
        const uint16_t rx_rings = 3,tx_rings = 3;
        uint16_t nb_rxd = RX_RING_SIZE;
        uint16_t nb_txd = TX_RING_SIZE;
        int ret;
        uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;
        if(!rte_eth_dev_is_valid_port(port)){
                printf("Port id:%d is not valid\n",port);
                return -1;
        }
        ret = rte_eth_dev_info_get(port, &dev_info);
        if(ret != 0){
                printf("Get info err @%u\n",port);
                return ret;
        }
	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			DEV_TX_OFFLOAD_MBUF_FAST_FREE;        
        ret =  rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
        if(ret != 0){
                return ret;
        }
        ret = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
        if(ret != 0){
                return ret;
        }
	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		ret = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (ret < 0)
			return ret;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		ret = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (ret < 0)
			return ret;
	}

	/* Start the Ethernet port. */
	ret = rte_eth_dev_start(port);
	if (ret < 0)
		return ret;

	/* Display the port MAC address. */
	struct rte_ether_addr addr;
	ret = rte_eth_macaddr_get(port, &addr);
	if (ret != 0)
		return ret;

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	ret = rte_eth_promiscuous_enable(port);
	if (ret != 0)
		return ret;

	return 0;
}
int
main(int argc, char **argv)
{
        struct rte_mempool *mbuf_pool;
        int ret;
        unsigned lcore_id;
        unsigned portid;
        int nb_lcore;
        int nb_port;

        ret = rte_eal_init(argc, argv);
        nb_lcore = rte_lcore_count();
        nb_port = rte_eth_dev_count_avail();
        if (ret < 0)
                rte_panic("Cannot init EAL\n");
        printf("Number of available port: %d\n",nb_port);
        printf("Number of lcore: %d\n",nb_lcore);
        if(nb_port % 2 == 1){
                rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");
        }
        mbuf_pool = rte_mempool_create("MBUF_POOL",
                               NUM_MBUFS * nb_port * nb_lcore,
                               RTE_MBUF_DEFAULT_BUF_SIZE,
                               MBUF_CACHE_SIZE,
                               sizeof(struct rte_pktmbuf_pool_private),
                               rte_pktmbuf_pool_init, NULL,
                               rte_pktmbuf_init,      NULL,
                               rte_socket_id(),
                               0);
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
        RTE_ETH_FOREACH_DEV(portid){
                if(port_init(portid,mbuf_pool) != 0){
 			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);                       
                }
        }        
        RTE_LCORE_FOREACH_SLAVE(lcore_id) {
                rte_eal_remote_launch(lcore_job, NULL, lcore_id);
        }


        lcore_job(NULL);

        rte_eal_mp_wait_lcore();
        return 0;
}
