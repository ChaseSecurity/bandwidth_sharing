import json

zoomeye_ttech_file = ""
zoomeye_ttnode_file =""
"""
ip,port,timestamp,city_name_EN
统计指标：
fofa,zoomeye各自的：unique_ip(ip+port),year分布，地理位置分布，端口分布
两者之和，总数据的：unique_ip(ip+port),year分布，地理位置分布，端口分布

"""
unique_ip = {}
# zoomeye__ip1 = './data/zoomeye/'
zoomeye_ip = set()
zoomeye_port = []
zoomeye_timestamp = []
zoomeye_city_name_EN = []
count = 0 
with open(zoomeye_ttech_file,'r') as fd:
    # global zoomeye_ip
    for line in fd.readlines():
#         print('111')
#         print(line)
#         break
        item = json.loads(line)
        ip = item['ip']
        port = item.get('port')
        lastupdatetime = item.get('timestamp')
        region = item.get('city_name_EN')
        
        # print(type(ip),ip)
        if isinstance (ip, list): 
            # if len(ip)>1:
            #     print(2)
            # for ip_ in ip:
            zoomeye_ip.add(ip[0])
        else:
            zoomeye_ip.add(ip)  
        zoomeye_port.append(port)
        zoomeye_timestamp.append(lastupdatetime)
        zoomeye_city_name_EN.append(region)
        print(port,lastupdatetime,ip)
        unique_ip[ip] = [{port:1},{lastupdatetime:1},{}]

        if ip not in unique_ip:
            count = count + 1
            if region != '':
                unique_ip[ip][2] = region
        else:
            if port not in unique_ip[ip][0]:
                count = count+1
                unique_ip[ip][0][port] =1
            else:
                unique_ip[ip][0][port]+=1
"""
            
f2=open(zoomeye_ttnode_file,'r',encoding='utf-8')
for line in f2:
    item = json.loads(line.strip())
    ip = item['ip']
    port = item.get('port')
    lastupdatetime = item.get('timestamp')
    region = item.get('city_name_EN')
    zoomeye_ip.add(ip)
    zoomeye_port.append(port)
    zoomeye_timestamp.append(lastupdatetime)
    zoomeye_city_name_EN.append(region)
    if ip not in unique_ip:
        count = count+1
        unique_ip[ip]=[{port:1},{lastupdatetime:1},{}] #port,lastupdatetime,city
        if region!='':
            unique_ip[ip][2][region]=1
    else:
        if port not in unique_ip[ip][0]:
            count = count+1
            unique_ip[ip][0][port]=1
        else:
            unique_ip[ip][0][port]+=1
        if lastupdatetime not in unique_ip[ip][1]:
            unique_ip[ip][1][lastupdatetime]=1
        else:
            unique_ip[ip][1][lastupdatetime]+=1
        if region !='':
            if region not in unique_ip[ip][2]:
                unique_ip[ip][2][region]=1
            else:
                unique_ip[ip][2][region]+=1
                
print("unique ip counts: ",len(unique_ip))
print("counts is ",count)

"""