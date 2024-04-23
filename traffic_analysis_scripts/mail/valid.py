import json
import pyshark
import sys
import os.path


def get_mail():

    blocked_ips=[]

    files_path=[]
    server_information={}  #server_host -> ips_ports,ips,ports,from,to,from_to_content
    src_ips=['172.19.0.2','172.19.0.3','172.19.0.4']

    try:
        input_json=open('read.json','r')
        input_stat=json.load(input_json)
        files_path=input_stat['files_path']
        all_tcp_len=input_stat['all_tcp_len']
        smtp_len=input_stat['smtp_len']
        all_stream=input_stat['all_stream']
        smtp_stream=input_stat['smtp_stream']
        server_information=input_stat['server_information']
    except:
        print("没有read.json文件")
        return

    need_servers=['opmta1mto18nd1','com.au','','opmta1mto09nd1','opmta1mto06nd1','pt.lu','opmta1mto10nd1',
    'opmta1mto29nd1','opmta1mto15nd1','ESMTP','hot.ee\\\r\\','Safe','welcome','Source','Mail2World',
    '0.0','Welcome'
    ]

    no_send_num=0
    output_txt=open('no_send.txt','w')
    need_server_txt=open('need_server.txt','w')
    for server, information in server_information.items():
        if server in need_servers:
            need_server_txt.write(server+"\n")
            for i in range(len(information[5])):
                need_server_txt.write(information[5][i][2]+"\n")
            need_server_txt.write("\n\n")
        for i in range(len(information[5])):
            if information[5][i][5]<=4:
                no_send_num+=1
                output_txt.write(information[5][i][2]+"\n\n")

    print('no_send_num:',no_send_num)

def main():
    print("正在处理")
    get_mail()
    print("处理完成")


if __name__ == "__main__":
    main()
