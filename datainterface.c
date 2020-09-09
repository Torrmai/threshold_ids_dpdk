#include <stdio.h>
#include <sys/stat.h>
#include <sqlite3.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include "datainterface.h"
#define UPDATE 8
#define INSERT 9
int ch;

FILE *target_file;
static int callback_printdata(void *data,int argc,char **argv,char **azColName)
{

    for (int i = 0; i < argc; i++)
    {
        printf("| %s |\t",argv[i] ? argv[i]:"NULL");
    }
    printf("\n");
    return 0;
}
static int callback_printlog(void *data,int argc,char **argv,char **azColName)
{
   for(int i=0;i<argc;i++){
      if(i<argc-1){
         fprintf(target_file,"%s,",argv[i]?argv[i]:"NULL");
      }
      else{
         fprintf(target_file,"%s",argv[i]?argv[i]:"NULL");
      }
   }
   fprintf(target_file,"\n");
   return 0;
}
static int fetch_data(void *data,int argc,char **argv,char **colname){
   for(int i = 0;i<argc;i++){
      ch = atoi(argv[i]);
   }
   return 0;
}
void calculate_matrix(sqlite3 *db){
   int stat;
   char *err = 0;
   stat = sqlite3_exec(db,"update ip_stat set pac_per_sec = count/60.0, tp = sum_tot_size/60.0",
                        callback_printdata,0,&err);
   if(stat != SQLITE_OK){
      printf("err: %s\n",err);
   }  
}
void create_res_perform(){
   
}
void create_log(sqlite3 *db,unsigned long np,uint32_t tot_s){//,char *sort_option){ reserve for near future
   time_t t = time(NULL);
   struct stat st = {0};
   char path[100];
   char tmp1[9];
   char sep1[50];
   char sep2[50];
   char fileName[200];
   char linCom[110];
   int statt;
   char *err = 0;
   calculate_matrix(db);
   struct tm currtime = *localtime(&t);
   sprintf(path,"data/%d/%d/%d/%d",(currtime.tm_year+1900),currtime.tm_mon+1,currtime.tm_mday,currtime.tm_hour);
   sprintf(tmp1,"data/%d",(currtime.tm_year+1900));
   sprintf(sep1,"data/%d/%d",(currtime.tm_year+1900),currtime.tm_mon+1);
   sprintf(sep2,"data/%d/%d/%d",(currtime.tm_year+1900),currtime.tm_mon+1,currtime.tm_mday);
   if(stat(path,&st)== -1){
      mkdir("data",0755);
      mkdir(tmp1,0755);
      mkdir(sep1,0755);
      mkdir(sep2,0755);
      mkdir(path,0755);
      printf("Create folder:%s....\n",path);
   }
   sprintf(fileName,"%s/%d.csv",
            path,currtime.tm_min);
   target_file = fopen(fileName,"w+");
   if(target_file == NULL){
      printf("Null file can't create file....\n");
      exit(0);
   }else{
      fprintf(target_file,"ip_addr,dst_port,ip version,end point,packet(pps),Throughput(bps),l4_pro\n");
      char comm[100];
      sprintf(comm,"select ip_addr,port,ip_type,end_point,round(pac_per_sec,2),round(tp,2),l4_pro from ip_stat "\
                   "order by count DESC");
      statt = sqlite3_exec(db,comm,callback_printlog,0,&err);
      if(statt != SQLITE_OK){
         printf("err: %s\n",err);
      }
      fprintf(target_file,"tot packet,tot size\n %d,%d\n",np,tot_s);
      fclose(target_file);
      printf("Log file: %s has been created successfully\n",fileName);
      //Now it's like triger function
      sprintf(comm,"delete from ip_stat");
      statt = sqlite3_exec(db,comm,callback_printdata,0,&err);
      if(statt != SQLITE_OK){
         printf("err: %s\n",err);
      }
   }
}
void conclude_stat(sqlite3 *db,char *target){
   int stat;
   const char *data = "Rank: ";
   char *err = 0;
   // char *comm = "select * from ip_stat_src "\
   //              "order by count DESC limit 10";
   char comm[300];
   sprintf(comm,"select * from ip_stat_%s "\
         "order by count DESC limit 10",target);
   printf("| ip |\t| port |\t| count |\t| sum size |\n");
   stat = sqlite3_exec(db,comm,callback_printdata,0,&err);
   if(stat != SQLITE_OK){
      printf("err: %s\n",err);
   }
   //temporary solution
   /*
   stat = sqlite3_exec(db,"delete from ip_stat",callback_printdata,0,&err);
   if(stat != SQLITE_OK){
      printf("err: %s\n",err);
   }*/
}
void insert_data(sqlite3 *db,uint32_t ip,uint32_t pkt_size)
{
   char sqlcom[300];
   sqlcom[0] = 0;
   int stat;
   char *err = 0;
   sprintf(sqlcom,"insert into ip_stat (ip_addr,size) "\
                  "values (%d,%d)"\
               ,ip,pkt_size);
   stat = sqlite3_exec(db,sqlcom,callback_printdata,0,&err);
   if (stat != SQLITE_OK)
   {
      printf("Error occur at insert\n");
      printf("sql err: %s\n",err);
      //printf(sqlcom);
      sqlite3_free(err);
   }
}
void create_tbl(sqlite3 *db){
   const char comm[300];
   char *err = 0;
   int stat;
   sprintf(comm,"create table ip_stat("\
         "ip_addr int not null,"\
         "port int,"\
         "size int not null,"\
         "l4_pro int,"\
         "match_net int)");
   stat = sqlite3_exec(db,comm,callback_printdata,0,&err);
   if (stat != SQLITE_OK)
   {
      printf("sql err: %s\n",err);
      sqlite3_free(err);
      exit(1);
   }
   else{
      printf("Create ip_stat\n");
   }
}