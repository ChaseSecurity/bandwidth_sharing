import json


try:
    input_json=open('read.json','r')
    input_stat=json.load(input_json)
    files_path=input_stat['files_path']
    server_information=input_stat['server_information']
except:
    print("没有read.json文件")

ips = {}

for server,information in server_information.items():
    print(information[0])
    for ip in information[0]:
        ips.add(ip)

print(ips)
f = open('server_ip.json','w')
json.dump(ips,f)