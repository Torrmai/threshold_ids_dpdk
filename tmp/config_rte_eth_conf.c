struct rte_eth_conf port_conf = {
  .rxmode = {
    .mq_mode = ETH_MQ_RX_RSS,
  },
  .rx_adv_conf = {
    .rss_conf = {
        .rss_key = hash_key,
        .rss_key_len = RSS_HASH_KEY_LENGTH,
        .rss_hf = ETH_RSS_IP |
              ETH_RSS_TCP |
              ETH_RSS_UDP |
              ETH_RSS_SCTP,
    }
   },
};