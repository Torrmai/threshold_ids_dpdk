#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <rte_ip.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <yaml.h>
#include "data_structure.h"
int write_time = 0;
int isVerbose = 0;
int elem_lim;
int printAll;
uint64_t tcp_port_lim[65536];
uint64_t time_peroid = 10;
uint64_t real_seconds;
uint32_t lim_addr[RECORD_ENTIRES];
struct diy_hash  host_lim[RECORD_ENTIRES];
head_t head;
int init_host_lim(){
    uint32_t ipaddr;
    int idx = 0;
    FILE *fp = fopen("config.yaml","r");
    yaml_parser_t parser;
    yaml_event_t event;
    bool isKey =false;
    bool main_map = true;
    if(!yaml_parser_initialize(&parser)){
        printf("Failed to initialize parser!\n");
        return -1;
    }
    yaml_parser_set_input_file(&parser,fp);
    struct node *e = NULL;
    char keys[255];
    char mapping_name[255][1000];
    int mapping_index = 0;
    int a[4];
    int res;
    int full_check = 0;
    //char pairValue[255];
    do
    {
        if(!yaml_parser_parse(&parser,&event)){
            printf("parser error %d\n",parser.error);
            exit(EXIT_FAILURE);
        }
        switch (event.type)
        {
        case YAML_NO_EVENT:break;
        case YAML_STREAM_START_EVENT:break;
        case YAML_STREAM_END_EVENT:break;
        //process delimeters
        case YAML_DOCUMENT_START_EVENT:break;
        case YAML_DOCUMENT_END_EVENT:break;
        case YAML_SEQUENCE_START_EVENT:break;
        case YAML_SEQUENCE_END_EVENT:break;
        case YAML_MAPPING_START_EVENT:
            //printf("isKey %d\n",isKey);
            mapping_index++;
            if (!isKey && ! main_map){ 
                sprintf(mapping_name[mapping_index],"%s",keys);
            }
            else{
                main_map = false;
                sprintf(mapping_name[mapping_index],"main");
            }
            isKey = true;
            break;
        case YAML_MAPPING_END_EVENT:
            mapping_index--;
            break;
        //data
        case YAML_ALIAS_EVENT:
            break;
        case YAML_SCALAR_EVENT:
            if (isKey)
            {
                //printf("%s\n",event.data.scalar.value);
                sprintf(keys,"%s",event.data.scalar.value);
                if (!strcmp(mapping_name[mapping_index],"Host_Mbit_per_sec") || !strcmp(mapping_name[mapping_index],"Host_packet_per_sec"))
                {
                    int i=0;
                    char *token = strtok(event.data.scalar.value,".");
                    while (token != NULL)
                    {
                        a[i] = strtol(token,NULL,10);
                        token = strtok(NULL,".");
                        i++;
                    }
                }              
                isKey=false;
            }
            else{ 
                isKey=true;
                if (keys == "num_rules"){
                    printf("%s----->%d\n",keys,strtol(event.data.scalar.value,NULL,10));
                }
                else if (keys == "time_interval")
                {
                    time_peroid = strtold(event.data.scalar.value,NULL);
                    real_seconds = time_peroid;
                }
                else if (!strcmp(keys,"verbose"))
                {
                    isVerbose = !strcmp(event.data.scalar.value,"true")? 1:0;
                }
                else if(!strcmp(keys,"dump_all")){
                    printAll = !strcmp(event.data.scalar.value,"true")? 1:0;
                }

                if(!strcmp(mapping_name[mapping_index],"Host_Mbit_per_sec"))
                {
                    ipaddr = RTE_IPV4(a[3],a[2],a[1],a[0]);
                    res = ipaddr%RECORD_ENTIRES;
                    if(host_lim[res].size_of_this_p == 0){
                        printf("Not collide\n");
                        lim_addr[idx] = ipaddr;
                        host_lim[res].size_of_this_p = strtoll(event.data.scalar.value,NULL,10)*(10*10*10*10*10*10)*time_peroid;
                        host_lim[res].next = NULL;
                        idx++;
                        elem_lim = idx;
                        full_check =elem_lim;
                        //host_lim[res].size_of_this_p = 0;
                        host_lim[res].realaddr = ipaddr;
                        host_stat[res][0].realaddr = ipaddr;
                        host_stat[res][1].realaddr = ipaddr;
                        host_stat[res][0].next = NULL;
                        host_stat[res][1].next = NULL;
                    }
                    else{
                        printf("collide\n");
                        host_lim[res].is_alert = 1;//collision leaw
                        int minus_flag = 0;
                        diy_elem *curr = &host_lim[res];
                        while (curr->next != NULL)
                        {
                            curr = curr->next;
                        }
                        curr->next = (diy_elem *)malloc(sizeof(diy_elem));
                        curr->next->realaddr = ipaddr;
                        curr->next->size_of_this_p = strtoll(event.data.scalar.value,NULL,10)*(10*10*10*10*10*10)*time_peroid;
                        curr->next->next = NULL;
                        diy_elem *test = &host_stat[res][0];
                        while (test->next != NULL)
                        {
                            test = test->next;
                        }
                        test->next = (diy_elem *)malloc(sizeof(diy_elem));
                        test->next->realaddr = ipaddr;
                        test->next->size_of_this_p = 0;
                        test->next->next =NULL;
                        diy_elem *curr2 = &host_stat[res][0];
                        while (curr2->next != NULL)
                        {
                            curr2 = curr2->next;
                        }
                        curr2->next = (diy_elem *)malloc(sizeof(diy_elem));
                        curr2->next->realaddr = ipaddr;
                        curr2->next->size_of_this_p = 0;
                        curr2->next->next = NULL;
                    }

                }
                else if(!strcmp(mapping_name[mapping_index],"tcp_port_limit_Mbit_per_sec")){
                    int tmp_index = atoi(keys);
                    tcp_port_lim[tmp_index] = atoi(event.data.scalar.value)*(10*10*10*10*10*10*time_peroid);
                    printf("%d %"PRIu64"\n",tmp_index,tcp_port_lim[tmp_index]);
                }
                else if(!strcmp(mapping_name[mapping_index],"udp_port_limit_Mbit_per_sec")){
                    int tmp_index = atoi(keys);
                    udp_port_lim[tmp_index] = atoi(event.data.scalar.value)*(10*10*10*10*10*10*time_peroid);
                }
            }
            break;
        default: break;
        }
        if (event.type != YAML_STREAM_END_EVENT)
        {
            yaml_event_delete(&event);
        }
        
    } while (event.type != YAML_STREAM_END_EVENT);
    yaml_event_delete(&event);
    yaml_parser_delete(&parser);
    fclose(fp);
    return 0;
}
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
                    if(ipv4_stat[res][curr_tb].is_alert){
                        fprintf(fp,"%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"",
                            (key_list[i][curr_tb].ipv4_addr&0xff),
                            (key_list[i][curr_tb].ipv4_addr >> 8)&0xff,
                            (key_list[i][curr_tb].ipv4_addr >> 16)&0xff,
                            (key_list[i][curr_tb].ipv4_addr >> 24)&0xff
                            );
                        fprintf(fp,",%"PRIu16",",key_list[i][curr_tb].src_port);
                        fprintf(fp,"%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"",
                            (key_list[i][curr_tb].ipv4_addr_dst&0xff),
                            (key_list[i][curr_tb].ipv4_addr_dst >> 8)&0xff,
                            (key_list[i][curr_tb].ipv4_addr_dst >> 16)&0xff,
                            (key_list[i][curr_tb].ipv4_addr_dst >> 24)&0xff
                            );                        
                        fprintf(fp,",%"PRIu16",%"PRIu8,key_list[i][curr_tb].dst_port,key_list[i][curr_tb].l3_pro);
                        fprintf(fp,",%"PRIu64",%"PRIu64,ipv4_stat[res][curr_tb].size_of_this_p * 8,ipv4_stat[res][curr_tb].n_pkt);
                        fprintf(fp,",%d\n",ipv4_stat[res][curr_tb].is_alert);
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
                    if(ipv4_cli[res][curr_tb].is_alert)
                    {
                        //print_ip(fp,key_list_cli[i][curr_tb].ipv4_addr);
                        fprintf(fp,"%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"",
                            (key_list_cli[i][curr_tb].ipv4_addr&0xff),
                            (key_list_cli[i][curr_tb].ipv4_addr >> 8)&0xff,
                            (key_list_cli[i][curr_tb].ipv4_addr >> 16)&0xff,
                            (key_list_cli[i][curr_tb].ipv4_addr >> 24)&0xff
                            );
                        fprintf(fp,",%"PRIu16",",key_list_cli[i][curr_tb].src_port);
                        //print_ip(fp,key_list_cli[i][curr_tb].ipv4_addr_dst);
                        fprintf(fp,"%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"",
                            (key_list_cli[i][curr_tb].ipv4_addr_dst&0xff),
                            (key_list_cli[i][curr_tb].ipv4_addr_dst >> 8)&0xff,
                            (key_list_cli[i][curr_tb].ipv4_addr_dst >> 16)&0xff,
                            (key_list_cli[i][curr_tb].ipv4_addr_dst >> 24)&0xff
                            );
                        fprintf(fp,",%"PRIu16",%"PRIu8,key_list_cli[i][curr_tb].dst_port,key_list_cli[i][curr_tb].l3_pro);
                        fprintf(fp,",%"PRIu64",%"PRIu64,ipv4_cli[res][curr_tb].size_of_this_p * 8,ipv4_cli[res][curr_tb].n_pkt);
                        fprintf(fp,",%d\n",ipv4_cli[res][curr_tb].is_alert);
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