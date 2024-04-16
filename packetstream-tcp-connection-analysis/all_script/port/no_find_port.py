from cmath import inf
import json
import sys
import os.path

def get_other_port(file_name,argv):
    #filename='/home/rhhuang/script/v4_stat/packetstream_vps5_2022-09-13_17-07-49.pcap_.json'

    json_file=open(file_name,'r')
    information_json=json.load(json_file)
    number_informations=information_json['number_informations']
    base_time=information_json['base_time']
    filename=information_json['filename']
    #domain_ips=information_json['domain_ips']
    #ip_domains=information_json['ip_domains']
    #stream_ip_number=information_json['stream_ip_number']
    #stream_timestamp=information_json['stream_timestamp']
    #domain_streams=information_json['domain_streams']
    #stream_len=information_json['stream_len']
    #ip_domains_number=information_json['ip_domains_number']
    #stream_numbers=information_json['stream_numbers']
    #all_len=information_json['all_len']
    #all_base_tcp_len=information_json['all_base_tcp_len']

    src_ips=['172.19.0.2','172.19.0.3','172.19.0.4']
    no_require_port=['80','443']
    if len(argv)>2:
        no_require_port+=argv[2:]
    no_require_host=['proxy.packetstream.io','api.packetstream.io']
    stream__information={}
    host_information={}
    files_path=[]
    try:
        input_json=open('port.json','r')
        input_stat=json.load(input_json)
        host_information=input_stat['host_information']
        files_path=input_stat['files_path']
        input_json.close()
    except:
        print("没有json文件")

    if os.path.basename(filename) in files_path:
        print("该文件已经被处理过，跳过处理！")
        return 
    files_path.append(os.path.basename(filename))
    files_path.sort()


    #                     0            1          2               3            4           5           6               7     8
    # information=[pkg.ip.src, pkg.ip.dst,pkg.tcp.srcport,pkg.tcp.dstport,int(pkg.length),pkg.tcp.stream,'',pkg.sniff_timestamp,'']

    for number,information in number_informations.items():
        if information[0] not in src_ips:
            if information[2] in no_require_port:
                continue
            if information[5] not in stream__information: # 0_ip        1_port         2_length       3_timestamp              4_host
                stream__information[information[5]]=[information[0],information[2],information[4],float(information[7]),[]]
                if information[8]!='':
                    stream__information[information[5]][4].append(information[8])
            else:
                stream__information[information[5]][2]+=information[4]
                if information[8]!='' and information[8] not in stream__information[information[5]][4]:
                    stream__information[information[5]][4].append(information[8])
        else:
            if information[3] in no_require_port:
                continue
            if information[5] not in stream__information: # 0_ip        1_port         2_length       3_timestamp              4_hosts
                stream__information[information[5]]=[information[1],information[3],information[4],float(information[7]),[]]
                if information[8]!='':
                    stream__information[information[5]][4].append(information[8])
            else:
                stream__information[information[5]][2]+=information[4]
                if information[8]!='' and information[8] not in stream__information[information[5]][4]:
                    stream__information[information[5]][4].append(information[8])

    for stream,information in stream__information.items():
        can_continue=False
        for host in information[4]:
            if host in no_require_host:
                can_continue=True
                break
        if can_continue:
            continue
        if len(information[4])==0:
            information[4].append(information[0])
        
        for host in information[4]:
            if host not in host_information:
                host_information[host]={}
                host_information[host][information[1]]=[0,{}]
                host_information[host][information[1]][0]+=information[2]
                host_information[host][information[1]][1][os.path.basename(filename)]=([information[2],[information[3]]])
            else:
                if information[1] not in host_information[host]:
                    host_information[host][information[1]]=[0,{}]
                    host_information[host][information[1]][0]+=information[2]
                    host_information[host][information[1]][1][os.path.basename(filename)]=([information[2],[information[3]]])
                else:
                    host_information[host][information[1]][0]+=information[2]
                    if os.path.basename(filename) not in host_information[host][information[1]][1]:
                        host_information[host][information[1]][1][os.path.basename(filename)]=([information[2],[information[3]]])
                    else:
                        host_information[host][information[1]][1][os.path.basename(filename)][0]+=information[2]
                        host_information[host][information[1]][1][os.path.basename(filename)][1].append(information[3])

    port_txt=open('port.txt','w')            
    for host,information in host_information.items():
        port_txt.write(host+"\n")
        for port,length_file_array in information.items():
            port_txt.write("\t端口:"+port+",长度:"+str(length_file_array[0])+"\n")
            for filename,length_timestamp_array in length_file_array[1].items():
                port_txt.write("\t\t"+filename+","+str(length_timestamp_array[0])+"\n")  #+","+str(length_timestamp_array[1])
        port_txt.write("\n")
    port_txt.close()

    output_json=open('port.json','w')
    output_stat={}
    output_stat['files_path']=files_path
    output_stat['host_information']=host_information
    json.dump(output_stat,output_json)
    output_json.close()

def main():
    print("正在处理文件：",sys.argv[1])
    get_other_port(sys.argv[1],sys.argv)
    print("处理文件完成：",sys.argv[1])


if __name__ == "__main__":
    main()

