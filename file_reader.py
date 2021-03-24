import os
import time
import threading
from collections import deque
from datetime import datetime
import glob
import sys
import pandas as pd
from influxdb import InfluxDBClient
serv_que = deque()
cli_que = deque()
class ToInflux(threading.Thread):
    def __init__(self, threadID, name, role):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.role = role
        self.running = True
        self.cli = InfluxDBClient(host='localhost',port=8086,username='username',password='password')
        self.cli.create_database("csv_transfrom")
        self.cli.switch_database("csv_transfrom")
    def run(self):
        last = ""
        if self.role == "server/IPv4":
            while self.running:
                while serv_que:
                    tmp = serv_que.pop()
                    new = tmp
                    if(last != new):
                        ts = tmp.split("/")
                        df = pd.read_csv(tmp)
                        self.post_host(df,ts[6].split(".")[0])
                        self.post_service(df,ts[6].split(".")[0])
                    last = new
        if self.role == "client/IPv4":
            while self.running:
                while cli_que:
                    tmp = cli_que.pop()
                    new = tmp
                    if(last != new):
                        ts = tmp.split("/")
                        df = pd.read_csv(tmp)
                        self.post_host(df,ts[6].split(".")[0])
                        self.post_service(df,ts[6].split(".")[0])
                    last = new
    def post_host(self,dt,ts):
        df = dt.groupby(['ip addr']).sum()
        df = df.sort_values(by='usage',ascending=False)
        df = df[0:10]
        tmp_tupple = {k:l for k,l in zip(df.index,df['usage'])}
        tmp_tupple2 = {k:l for k,l in zip(df.index,df["#packets"])}
        json_body =[]
        self.ip_src = [k for k in df.index]
        for i in tmp_tupple.keys():
            tmp_data = {"measurement":"top10_"+self.role.split("/")[0]}
            tmp_data["tags"]={'ip addr':i}
            tmp_data["time"]=datetime.utcfromtimestamp(int(ts)/1000).strftime('%Y-%m-%d %H:%M:%S')+'Z'
            tmp_data["fields"]={'usage':int(tmp_tupple[i])//(10**6),"freqeuncy":int(tmp_tupple2[i])}
            json_body.append(tmp_data)
        if(self.cli != None):
            try:
                self.cli.write_points(json_body)
            except:
                print(json_body)
    def post_service(self,dt,ts):
        json_body = []
        for x in self.ip_src:
            df = dt[dt['ip addr']==x]
            df = df.groupby(['Type of service']).sum()
            tmp_pps = {k:l for k,l in zip(df.index,df['#packets'])}
            tmp_usage = {k:l for k,l in zip(df.index,df["usage"])}
            for y in tmp_pps.keys():
                tmp_data = {"measurement":"Type of service count "+self.role.split("/")[0]}
                tmp_data["tags"] = {'ip addr':x,'Type of service':int(y)}
                tmp_data["time"]=datetime.utcfromtimestamp(int(ts)/1000).strftime('%Y-%m-%d %H:%M:%S')+'Z'
                tmp_data['fields']={'frequency':int(tmp_pps[y]),'usage':int(tmp_usage[y])//(10**6)}
                json_body.append(tmp_data)
            if(self.cli != None):
                try:
                    self.cli.write_points(json_body)
                except:
                    print(json_body)
class GetNewFile(threading.Thread):
    def __init__(self,threadID,name,role):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.role = role
        self.first_time = True
        self.running = True
    def run(self):
        while self.running:
            if not self.first_time:
                data_path = os.path.join(os.getcwd(),self.role)
                list_file = glob.glob(data_path+'/*.csv')
                self.latest_file = max(list_file,key=os.path.getctime)
                if self.role == "server/IPv4" and self.latest_file not in serv_que:
                    serv_que.append(self.latest_file)
                elif self.role == "client/IPv4":
                    cli_que.append(self.latest_file)
            else:
                data_path = os.path.join(os.getcwd(),self.role)
                for i in os.listdir(data_path):
                    tmp_path = os.path.join(data_path,i)
                    if(os.stat(tmp_path).st_size > 0):
                        if(self.role ==  "server/IPv4"):
                            serv_que.append(tmp_path)
                        elif(self.role == "client/IPv4"):
                            cli_que.append(tmp_path)
                self.first_time = False
    def stop(self):
        self.running = False
if __name__ == "__main__":
    serv_new = GetNewFile(1,"th1","server/IPv4")
    cli_new = GetNewFile(2,"th2","client/IPv4")
    serv_post = ToInflux(3,"th3","server/IPv4")
    cli_post = ToInflux(4,"th4","client/IPv4")
    try:
        #serv_new.deamon = True 
        serv_new.start()
        cli_new.start()
        serv_post.start()
        cli_post.start()
    except (KeyboardInterrupt,SystemExit):
        serv_new.running = False
        serv_post.running = False
        cli_post.running = False
        cli_new.running =False
        serv_new.join()
        serv_post.join()
        cli_new.join()
        cli_post.join()
        sys.exit()
        