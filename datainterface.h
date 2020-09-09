#ifdef DATAINTERFACE
#include <sqlite3.h>
#include <stdio.h>
#include <sys/stat.h>
#include <stdint.h>
#include <rte_mbuf.h>
int ch;
typedef struct pkt_node{
    struct rte_mbuf *pkt;
    struct pkt_node *next;
}pkt_queue_node;
void conclude_stat(sqlite3 *db,int target);
void create_log(sqlite3 *db,unsigned long np,uint32_t tot_s);
void update_data(sqlite3 *db,char *data,int target,uint32_t pkt_size,uint16_t port,int l4_pro);
int data_choice(sqlite3 *db,char *ip,int target,uint16_t port,int l4_pro);
void insert_data(sqlite3 *db,char *ip,int target,uint16_t port,uint32_t pkt_size,int type,int l4_pro);
static int callback_printdata(void *data,int argc,char **argv,char **azColName);
void create_tbl(sqlite3 *db);
#endif
