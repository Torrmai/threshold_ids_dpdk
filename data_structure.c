#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <sys/time.h>
#include "data_structure.h"
int write_time = 0;
void print_IPv6(uint8_t addr[],FILE *f){
    if(addr != NULL){
        char tmp_addr[4];
        char ipv6_addr[40];
	    for (int i = 0; i < 16; i++)
	    {
	    	uint16_t tmp = addr[i];
	    	sprintf(tmp_addr,"%02x",tmp);
	    	strcat(ipv6_addr,tmp_addr);
	    	if(i%2 == 1 && i < 15){
	    		strcat(ipv6_addr,":");
	    	}
	    }
        fprintf(f,"%s",ipv6_addr);
        memset(ipv6_addr,0,sizeof(ipv6_addr)); 
    }
}
const char* show_IPv4(uint32_t addr){
    char tmp_addr[50];
    memset(tmp_addr,0,sizeof(tmp_addr));
    sprintf(tmp_addr,"%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8,
        (uint8_t)(addr & 0xff),
        (uint8_t)((addr >> 8) & 0xff),
        (uint8_t)((addr >> 16) & 0xff),
        (uint8_t)((addr >> 24) & 0xff));
    return tmp_addr;   
}
void print_ip(FILE *f,uint32_t addr){
    fprintf(f,"%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8,
        (uint8_t)(addr & 0xff),
        (uint8_t)((addr >> 8) & 0xff),
        (uint8_t)((addr >> 16) & 0xff),
        (uint8_t)((addr >> 24) & 0xff));
}

void write_log_v6(struct rte_hash *tb,char *target,int curr_tb)
{
    FILE *fp;
    char src_adr[16];
    char dst_addr[16];
    char path[1000];
    struct timeval tv;
    int res;
    int numelem = rte_hash_count(tb);
    if(write_time > 1 && numelem > 0){
        //print_IPv6(key_list6[0][curr_tb].ipv6_addr);
        //print_IPv6(key_list6[0][curr_tb].ipv6_addr_dst);
        /*for (int i = 0; i < numelem; i++)
        {
            print_IPv6(key_list6[i][curr_tb].ipv6_addr);
            print_IPv6(key_list6[i][curr_tb].ipv6_addr_dst);
        }*/
        
        gettimeofday(&tv,NULL);
        sprintf(path,"/home/chanawat/data/%s/IPv6/%"PRIu64".csv",target,(uint64_t)(tv.tv_sec)*1000 + (uint64_t)(tv.tv_usec)/1000);
        //printf("called %d\n",numelem);
        fp = fopen(path,"w+");
        fprintf(fp,"ip addr,src port,ip addr dst,dst port,Type of service,usage,#packets\n");
        if(target == "server"){
            for (int i = 0; i < numelem; i++)
            {
                if(((void *)&key_list6[i][curr_tb]) != NULL)
                {
                    res = rte_hash_lookup(tb,(void *)&key_list6[i][curr_tb]);
                    if(res < 0){
                        if(res == -EINVAL){
                            printf("error\n");
                        }
                    }
                    else
                    {
                        print_IPv6(key_list6[i][curr_tb].ipv6_addr,fp);
                        fprintf(fp,",%"PRIu16",",key_list[i][curr_tb].src_port);
                        print_IPv6(key_list6[i][curr_tb].ipv6_addr_dst,fp);
                        fprintf(fp,",%"PRIu16",%"PRIu8,key_list6[i][curr_tb].dst_port,key_list6[i][curr_tb].l3_pro);
                        fprintf(fp,",%"PRIu64",%"PRIu64"\n",ipv6_stat[res][curr_tb].size_of_this_p * 8,ipv6_stat[res][curr_tb].n_pkt);
                    }
                    //reset value
                    ipv6_stat[res][curr_tb].n_pkt = 0;
                    ipv6_stat[res][curr_tb].size_of_this_p = 0;
                }
            }
            fclose(fp);
        }
        /*else if(target == "client"){
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
                    fprintf(fp,",%"PRIu64",%"PRIu64"\n",ipv4_cli[res][curr_tb].size_of_this_p * 8,ipv4_cli[res][curr_tb].n_pkt);
                }
                //reset value
                ipv4_cli[res][curr_tb].size_of_this_p = 0;
                ipv4_cli[res][curr_tb].n_pkt = 0;
            }
            fclose(fp);
        }*/
    }else{
        write_time++;
    }
}
void write_log_v4(struct rte_hash *tb,char *target,int curr_tb)
{
    FILE *fp;
    char path[1000];
    struct timeval tv;
    int res;
    int numelem = rte_hash_count(tb);
    if(write_time > 1 && numelem > 0){
        gettimeofday(&tv,NULL);
        sprintf(path,"/home/chanawat/data/%s/IPv4/%"PRIu64".csv",target,(uint64_t)(tv.tv_sec)*1000 + (uint64_t)(tv.tv_usec)/1000);
        //printf("called %d\n",numelem);
        fp = fopen(path,"w+");
        fprintf(fp,"ip addr,src port,ip addr dst,dst port,Type of service,usage,#packets\n");
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
                    if(ipv4_stat[res][curr_tb].size_of_this_p >0 && ipv4_stat[res][curr_tb].n_pkt >0){
                        print_ip(fp,key_list[i][curr_tb].ipv4_addr);
                        fprintf(fp,",%"PRIu16",",key_list[i][curr_tb].src_port);
                        print_ip(fp,key_list[i][curr_tb].ipv4_addr_dst);
                        fprintf(fp,",%"PRIu16",%"PRIu8,key_list[i][curr_tb].dst_port,key_list[i][curr_tb].l3_pro);
                        fprintf(fp,",%"PRIu64",%"PRIu64"\n",ipv4_stat[res][curr_tb].size_of_this_p * 8,ipv4_stat[res][curr_tb].n_pkt);
                    }
                    //reset value
                    ipv4_stat[res][curr_tb].size_of_this_p = 0;
                    ipv4_stat[res][curr_tb].n_pkt = 0;
                    ipv4_stat[res][curr_tb].is_alert = 0;
                }
                
            }
            fclose(fp);
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
                    if(ipv4_cli[res][curr_tb].size_of_this_p > 0 &&ipv4_cli[res][curr_tb].n_pkt >0)
                    {
                        print_ip(fp,key_list_cli[i][curr_tb].ipv4_addr);
                        fprintf(fp,",%"PRIu16",",key_list_cli[i][curr_tb].src_port);
                        print_ip(fp,key_list_cli[i][curr_tb].ipv4_addr_dst);
                        fprintf(fp,",%"PRIu16",%"PRIu8,key_list_cli[i][curr_tb].dst_port,key_list_cli[i][curr_tb].l3_pro);
                        fprintf(fp,",%"PRIu64",%"PRIu64"\n",ipv4_cli[res][curr_tb].size_of_this_p * 8,ipv4_cli[res][curr_tb].n_pkt);
                    }
                    //reset value
                    rte_atomic64_set(&ipv4_cli[res][curr_tb].size_of_this_p,0);
                    rte_atomic64_set(&ipv4_cli[res][curr_tb].n_pkt,0);
                }

            }
            fclose(fp);
        }
    }else{
        write_time++;
    }
    memset(path,0,sizeof(path));
}