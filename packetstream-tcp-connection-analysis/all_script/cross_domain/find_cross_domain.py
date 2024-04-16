import json
import pyshark
import sys
import os.path


def get_cross_domain(file_name):
    json_file=open(file_name,'r')
    information_json=json.load(json_file)
    number_informations=information_json['number_informations']
    base_time=information_json['base_time']
    filename=information_json['filename']
    domain_ips=information_json['domain_ips']
    ip_domains=information_json['ip_domains']
    stream_ip_number=information_json['stream_ip_number']
    stream_timestamp=information_json['stream_timestamp']  #这个是有减去basetime的
    domain_streams=information_json['domain_streams']
    stream_len=information_json['stream_len']
    ip_domains_number=information_json['ip_domains_number']
    stream_numbers=information_json['stream_numbers']
    all_len=information_json['all_len']
    all_base_tcp_len=information_json['all_base_tcp_len']

    stream__information={}

    host_protocol_others_filename_streams={}
    files_path=[]

    src_domains=['proxy.packetstream.io','api.packetstream.io','api.honeygain.com']
    src_ips=['172.19.0.2','172.19.0.3','172.19.0.4']
#0:src_ip  1:dst_ip     2:src_port    3:dst_port  4:length        5:stream       6:protocol    7:timestamp     8:host   9:_info


    #read old data
    try:
        input_json=open('stat.json','r')
        input_stat=json.load(input_json)
        host_protocol_others_filename_streams=input_stat['host_protocol_others_filename_streams']
        files_path=input_stat['files_path']
        input_json.close()
    except:
        print("没有json文件")

    if os.path.basename(filename) in files_path:
        print("该文件已经被处理过，跳过处理！")
        return 
    files_path.append(os.path.basename(filename))
    files_path.sort()

    #deal with data
    for number,information in number_informations.items():
        if information[0] not in src_ips:
            if information[5] not in stream__information: # 0_ip        1_port         2_length       3_timestamp      4_host  5_protocol
                stream__information[information[5]]=[information[0],information[2],information[4],float(information[7]),[],[]]
                if information[8]!='':
                    stream__information[information[5]][4].append(information[8])
                if information[6] not in stream__information[information[5]][5]:
                    stream__information[information[5]][5].append(information[6])
            else:
                stream__information[information[5]][2]+=information[4]
                if information[8]!='' and information[8] not in stream__information[information[5]][4]:
                    stream__information[information[5]][4].append(information[8])
                if information[6] not in stream__information[information[5]][5]:
                    stream__information[information[5]][5].append(information[6])
        else:
            if information[5] not in stream__information: 
                stream__information[information[5]]=[information[1],information[3],information[4],float(information[7]),[],[]]
                if information[8]!='':
                    stream__information[information[5]][4].append(information[8])
                if information[6] not in stream__information[information[5]][5]:
                    stream__information[information[5]][5].append(information[6])
            else:
                stream__information[information[5]][2]+=information[4]
                if information[8]!='' and information[8] not in stream__information[information[5]][4]:
                    stream__information[information[5]][4].append(information[8])
                if information[6] not in stream__information[information[5]][5]:
                    stream__information[information[5]][5].append(information[6])

    
    for stream,information in stream__information.items():
        if len(information[4])>1:
            origin_host=information[4][0]
            if origin_host not in host_protocol_others_filename_streams:
                host_protocol_others_filename_streams[origin_host]=[[],{}]
                host_protocol_others_filename_streams[origin_host][0]=information[5]
            for host in information[4]:
                if host != origin_host:
                    if host not in host_protocol_others_filename_streams[origin_host][1]:
                        host_protocol_others_filename_streams[origin_host][1][host]={}
                        host_protocol_others_filename_streams[origin_host][1][host][filename]=[]
                        host_protocol_others_filename_streams[origin_host][1][host][filename].append(stream)
                    else:
                        if filename not in host_protocol_others_filename_streams[origin_host][1][host]:
                            host_protocol_others_filename_streams[origin_host][1][host][filename]=[]
                            host_protocol_others_filename_streams[origin_host][1][host][filename].append(stream)
                        else:
                            host_protocol_others_filename_streams[origin_host][1][host][filename].append(stream)

    # print data
    output_txt=open('stat.txt', 'w')
    output_txt.write("所有来源文件:\n")
    for file_name in files_path:
        output_txt.write(file_name+"\n")
    output_txt.write("\n")
    for origin_host,protocol_others_filename_streams in host_protocol_others_filename_streams.items():
        output_txt.write(origin_host+","+str(protocol_others_filename_streams[0])+"\n")
        for host,filename_streams in protocol_others_filename_streams[1].items():
            output_txt.write("\t"+host+"\n")
            for filename,streams in filename_streams.items():
                output_txt.write("\t\t"+filename+":"+str(streams)+"\n")
        output_txt.write("\n")

    # write data
    output_stat={}
    output_stat['host_protocol_others_filename_streams']=host_protocol_others_filename_streams
    output_stat['files_path']=files_path
    
    output_json=open('stat.json','w')
    json.dump(output_stat, output_json)
    output_json.close()

def main():
    print("正在处理文件：",sys.argv[1])
    get_cross_domain(sys.argv[1])
    print("处理文件完成：",sys.argv[1])


if __name__ == "__main__":
    main()
