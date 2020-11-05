#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <sys/time.h>
#include "data_structure.h"
int write_time = 0;
void print_ip(FILE *f,uint32_t addr){
    fprintf(f,"%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8,
        (uint8_t)(addr & 0xff),
        (uint8_t)((addr >> 8) & 0xff),
        (uint8_t)((addr >> 16) & 0xff),
        (uint8_t)((addr >> 24) & 0xff));
}
void write_log(struct rte_hash *tb,char *target,struct usage_stat data[][2],int curr_tb)
{
    FILE *fp;
    char path[255];
    struct timeval tv;
    int res;
    if(write_time > 1){
        int numelem = rte_hash_count(tb);
        gettimeofday(&tv,NULL);
        sprintf(path,"/home/chanawat/data/%s/%"PRIu64".csv",target,(uint64_t)(tv.tv_sec)*1000 + (uint64_t)(tv.tv_usec)/1000);
        //printf("called %d\n",numelem);
        fp = fopen(path,"w+");
        fprintf(fp,"ip addr,src port,ip addr dst,dst port,l3 proto,usage,#packets\n");
        if(target == "server"){
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

                    print_ip(fp,key_list[i][curr_tb].ipv4_addr);
                    fprintf(fp,",%"PRIu16",",key_list[i][curr_tb].src_port);
                    print_ip(fp,key_list[i][curr_tb].ipv4_addr_dst);
                    fprintf(fp,",%"PRIu16",%"PRIu8,key_list[i][curr_tb].dst_port,key_list[i][curr_tb].l3_pro);
                    fprintf(fp,",%"PRIu64",%"PRIu64"\n",data[res][curr_tb].size_of_this_p * 8,data[res][curr_tb].n_pkt);
                }
                
            }
        }
        else if(target == "client"){
            for (int i = 0; i < numelem; i++)
            {
                res = rte_hash_lookup(tb,(void *)&key_list_cli[i][curr_tb]);
                if(res < 0){
                    if(res == -EINVAL){
                        printf("error\n");
                    }
                    printf(res);
                }
                else
                {
                    print_ip(fp,key_list_cli[i][curr_tb].ipv4_addr);
                    fprintf(fp,",%"PRIu16",",key_list_cli[i][curr_tb].src_port);
                    print_ip(fp,key_list_cli[i][curr_tb].ipv4_addr_dst);
                    fprintf(fp,",%"PRIu16",%"PRIu8,key_list_cli[i][curr_tb].dst_port,key_list_cli[i][curr_tb].l3_pro);
                    fprintf(fp,",%"PRIu64",%"PRIu64"\n",data[res][curr_tb].size_of_this_p * 8,data[res][curr_tb].n_pkt);
                }
                
            }
            fclose(fp);
        }
    }else{
        write_time++;
    }

}