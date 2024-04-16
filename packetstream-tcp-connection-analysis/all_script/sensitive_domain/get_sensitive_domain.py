import json
import pyshark
import sys
import os.path


def get_domain_len(file_name):
    #file_name='/home/hrh/bandwidth_sharing/traffic_stats/v6_stat_program/honeygain_vps5_2022-09-13_17-12-27.pcap_v2.json'

    json_file=open(file_name,'r')
    information_json=json.load(json_file)
    number_informations=information_json['number_informations']
    #base_time=information_json['base_time']
    filename=information_json['filename']
    #domain_ips=information_json['domain_ips']
    #ip_domains=information_json['ip_domains']
    stream_ip_number=information_json['stream_ip_number']
    #stream_timestamp=information_json['stream_timestamp']
    domain_streams=information_json['domain_streams']
    stream_len=information_json['stream_len']
    ip_domains_number=information_json['ip_domains_number']
    stream_numbers=information_json['stream_numbers']
    #all_len=information_json['all_len']
    #all_base_tcp_len=information_json['all_base_tcp_len']

    sensitive_fields=['.edu','.gov']
    src_ips=['172.19.0.2','172.19.0.3','172.19.0.4']

    sensitive_domain_ports_filename_stream_length={}
    other_ip_ports_filename_stream_length={}
    files_path=[]
    #read old data
    try:
        input_json=open('stat.json','r')
        input_stat=json.load(input_json)
        sensitive_domain_ports_filename_stream_length=input_stat['sensitive_domain_ports_filename_stream_length']
        other_ip_ports_filename_stream_length=input_stat['other_ip_ports_filename_stream_length']
        files_path=input_stat['files_path']
        input_json.close()
    except:
        print("没有json文件")

    if os.path.basename(filename) in files_path:
        print("该文件已经被处理过，跳过处理！")
        return 
    files_path.append(os.path.basename(filename))
    files_path.sort()


    #deal with data --find sensitive domain
    for domain,streams in domain_streams.items():
        if domain in sensitive_domain_ports_filename_stream_length:
            if number_informations[stream_numbers[streams[0]][0]][0] not in src_ips:
                port=number_informations[stream_numbers[streams[0]][0]][1]
            else:
                port=number_informations[stream_numbers[streams[0]][0]][3]
            if port not in sensitive_domain_ports_filename_stream_length[domain]:
                sensitive_domain_ports_filename_stream_length[domain][port]={}
                sensitive_domain_ports_filename_stream_length[domain][port][filename]={}
                for stream in streams:
                    sensitive_domain_ports_filename_stream_length[domain][port][filename][stream]=stream_len[stream]
            else:
                if filename not in sensitive_domain_ports_filename_stream_length[domain][port]:
                    sensitive_domain_ports_filename_stream_length[domain][port][filename]={}
                    for stream in streams:
                        sensitive_domain_ports_filename_stream_length[domain][port][filename][stream]=stream_len[stream]
                else:
                    print("my wrong")
            continue
        for sensitive_field in sensitive_fields:
            if domain.find(sensitive_field)!=-1:
                if number_informations[stream_numbers[streams[0]][0]][0] not in src_ips:
                    port=number_informations[stream_numbers[streams[0]][0]][1]
                else:
                    port=number_informations[stream_numbers[streams[0]][0]][3]
                if domain not in sensitive_domain_ports_filename_stream_length:
                    sensitive_domain_ports_filename_stream_length[domain]={}
                    sensitive_domain_ports_filename_stream_length[domain][port]={}
                    if filename not in sensitive_domain_ports_filename_stream_length[domain][port]:
                        sensitive_domain_ports_filename_stream_length[domain][port][filename]={}
                        for stream in streams:
                            sensitive_domain_ports_filename_stream_length[domain][port][filename][stream]=stream_len[stream]
                    else:
                        print("my wrong")
                else:
                    
                    if port not in sensitive_domain_ports_filename_stream_length[domain]:
                        sensitive_domain_ports_filename_stream_length[domain][port]={}
                        sensitive_domain_ports_filename_stream_length[domain][port][filename]={}
                        for stream in streams:
                            sensitive_domain_ports_filename_stream_length[domain][port][filename][stream]=stream_len[stream]
                    else:
                        if filename not in sensitive_domain_ports_filename_stream_length[domain][port]:
                            sensitive_domain_ports_filename_stream_length[domain][port][filename]={}
                            for stream in streams:
                                sensitive_domain_ports_filename_stream_length[domain][port][filename][stream]=stream_len[stream]
                        else:
                            print("my wrong")
                break
    
    #find ip
    for domain, streams in domain_streams.items():
        # if domain == 'www.macphoto.cn':
        #     print(streams)
        #判断一下是不是纯ip
        can_continue=False
        for c in domain:
            if c.isalpha():
                can_continue=True
                break
        if can_continue:
            continue
        for stream in streams:
            stream_len[stream]=0

    for stream,length in stream_len.items():
        if length == 0:
            continue  
        if stream_ip_number[stream][0] in ip_domains_number:
            can_break=False
            for domain,numbers_dns in ip_domains_number[stream_ip_number[stream][0]].items():
                for number_dns in numbers_dns:
                    if 50 > stream_ip_number[stream][1]-number_dns > 0:  # 50个包以内就视为这个流的DNS查询
                        stream_len[stream]=0 
                    if can_break:
                        break
                if can_break:
                    break
    
    for stream,length in stream_len.items():
        if length == 0:
            continue 

        num=stream_ip_number[stream][1]
        if number_informations[str(num)][0] not in src_ips:
            ip=number_informations[str(num)][0]
            port=number_informations[str(num)][2]
        else:
            ip=number_informations[str(num)][1]
            port=number_informations[str(num)][3]
        if ip not in other_ip_ports_filename_stream_length:
            other_ip_ports_filename_stream_length[ip]={}
            other_ip_ports_filename_stream_length[ip][port]={}
            other_ip_ports_filename_stream_length[ip][port][filename]={}
            other_ip_ports_filename_stream_length[ip][port][filename][stream]=length
        else:
            if port not in other_ip_ports_filename_stream_length[ip]:
                other_ip_ports_filename_stream_length[ip][port]={}
                other_ip_ports_filename_stream_length[ip][port][filename]={}
                other_ip_ports_filename_stream_length[ip][port][filename][stream]=length
            else:
                if filename not in other_ip_ports_filename_stream_length[ip][port]:
                    other_ip_ports_filename_stream_length[ip][port][filename]={}
                    other_ip_ports_filename_stream_length[ip][port][filename][stream]=length
                else:
                    other_ip_ports_filename_stream_length[ip][port][filename][stream]=length

    # write data
    output_txt=open('stat.txt', 'w')
    output_txt.write("所有来源文件:\n")
    for file_name in files_path:
        output_txt.write(file_name+"\n")
    output_txt.write("\ns无域名ip:\n")
    for ip,ports_filename_stream_length in other_ip_ports_filename_stream_length.items():
        output_txt.write(ip+"\n")
        for port,others in ports_filename_stream_length.items():
            output_txt.write(port+"\n")
        output_txt.write("\n")
    output_txt.close()

    output2_txt=open('stat2.txt', 'w')
    output2_txt.write("所有来源文件:\n")
    for file_name in files_path:
        output2_txt.write(file_name+"\n")
    output2_txt.write("\nsensitive域名:\n")
    for sensitive_domain,ports_filename_stream_length in sensitive_domain_ports_filename_stream_length.items():
        output2_txt.write("域名:"+sensitive_domain+"\n")
        for port,others in ports_filename_stream_length.items():
            output2_txt.write("\t"+port+"\n")
        output2_txt.write("\n")
    output2_txt.close()

    output_stat={}
    output_stat['sensitive_domain_ports_filename_stream_length']=sensitive_domain_ports_filename_stream_length
    output_stat['other_ip_ports_filename_stream_length']=other_ip_ports_filename_stream_length
    output_stat['files_path']=files_path
    
    output_json=open('stat.json','w')
    json.dump(output_stat, output_json)
    output_json.close()

def main():
    print("正在处理文件：",sys.argv[1])
    get_domain_len(sys.argv[1])
    print("处理文件完成：",sys.argv[1])


if __name__ == "__main__":
    main()
