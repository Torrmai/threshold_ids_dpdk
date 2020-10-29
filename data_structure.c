#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <sys/time.h>
#include "data_structure.h"
void write_log(struct rte_hash *tb,char *target,int numelem,struct usage_stat data[][2],int curr_tb)
{
    FILE *fp;
    char path[255];
    struct timeval tv;
    int res;
    gettimeofday(&tv,NULL);
    sprintf(path,"/home/chanawat/data/%s/%"PRIu64".csv",target,(uint64_t)(tv.tv_sec)*1000 + (uint64_t)(tv.tv_usec)/1000);
    //printf("called %d\n",numelem);
    fp = fopen(path,"w+");
    fprintf(fp,"ip addr,src port,dst port,l3 proto,usage,#packets\n");
    for (int i = 0; i < numelem; i++)
    {
        res = rte_hash_lookup(tb,(void *)&key_list[i][curr_tb]);
        if(res < 0){
            if(res == -EINVAL){
                printf("error\n");
            }
            printf(res);
        }
        else
        {
            fprintf(fp,"%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8,
                (uint8_t)(key_list[i][curr_tb].ipv4_addr & 0xff),
                (uint8_t)((key_list[i][curr_tb].ipv4_addr >> 8) & 0xff),
                (uint8_t)((key_list[i][curr_tb].ipv4_addr >> 16) & 0xff),
                (uint8_t)((key_list[i][curr_tb].ipv4_addr >> 24) & 0xff));
            fprintf(fp,",%"PRIu16",%"PRIu16",%"PRIu8,
                    data[res][curr_tb].src_port,key_list[i][curr_tb].port,key_list[i][curr_tb].l3_pro);
            fprintf(fp,",%"PRIu64",%"PRIu64"\n",data[res][curr_tb].n_pkt,data[res][curr_tb].size_of_this_p);
        }
        
    }
    fclose(fp);
}