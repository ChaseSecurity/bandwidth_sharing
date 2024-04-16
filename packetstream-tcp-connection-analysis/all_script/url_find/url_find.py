import json
import pyshark
import sys
import os.path


def url_find(file_name,argv):
    json_file=open(file_name,'r')
    information_json=json.load(json_file)
    number_informations=information_json['number_informations']
    base_time=information_json['base_time']
    filename=information_json['filename']
    domain_ips=information_json['domain_ips']
    ip_domains=information_json['ip_domains']
    stream_ip_number=information_json['stream_ip_number']
    stream_timestamp=information_json['stream_timestamp']
    domain_streams=information_json['domain_streams']
    stream_len=information_json['stream_len']
    ip_domains_number=information_json['ip_domains_number']
    stream_numbers=information_json['stream_numbers']
    #all_len=information_json['all_len']
    #all_base_tcp_len=information_json['all_base_tcp_len']

    sensitive_fields=[]
    if len(argv)>2:
        sensitive_fields+=argv[2:]

    src_ips=['172.19.0.2','172.19.0.3','172.19.0.4']

    domain_number_filename_stream_url={}
    files_path=[]
    #read old data
    try:
        input_json=open('stat.json','r')
        input_stat=json.load(input_json)
        domain_number_filename_stream_url=input_stat['domain_number_filename_stream_url']
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
        if information[6]=='tls':
            for field in sensitive_fields:
                if information[8].find(field)!=-1:
                    if information[8] not in domain_number_filename_stream_url:
                        domain_number_filename_stream_url[information[8]]=[1,{}]
                        domain_number_filename_stream_url[information[8]][1][filename]={}
                        domain_number_filename_stream_url[information[8]][1][filename][information[5]]="https://"+information[8]
                    else:
                        domain_number_filename_stream_url[information[8]][0]+=1
                        if filename not in domain_number_filename_stream_url[information[8]][1]:
                            domain_number_filename_stream_url[information[8]][1][filename]={}
                            domain_number_filename_stream_url[information[8]][1][filename][information[5]]="https://"+information[8]
                        else:
                            domain_number_filename_stream_url[information[8]][1][filename][information[5]]="https://"+information[8]
        elif information[6]=='http':
            if 'request_full_uri' in information[9]:
                for field in sensitive_fields:
                    if information[9]['request_full_uri'].find(field)!=-1:
                        if information[8] not in domain_number_filename_stream_url:
                            domain_number_filename_stream_url[information[8]]=[1,{}]
                            domain_number_filename_stream_url[information[8]][1][filename]={}
                            domain_number_filename_stream_url[information[8]][1][filename][information[5]]=information[9]['request_full_uri']
                        else:
                            domain_number_filename_stream_url[information[8]][0]+=1
                            if filename not in domain_number_filename_stream_url[information[8]][1]:
                                domain_number_filename_stream_url[information[8]][1][filename]={}
                                domain_number_filename_stream_url[information[8]][1][filename][information[5]]=information[9]['request_full_uri']
                            else:
                                domain_number_filename_stream_url[information[8]][1][filename][information[5]]=information[9]['request_full_uri']
    
    
    
    #find ip
    # for domain, streams in domain_streams.items():
    #     # if domain == 'www.macphoto.cn':
    #     #     print(streams)
    #     #判断一下是不是纯ip
    #     can_continue=False
    #     for c in domain:
    #         if c.isalpha():
    #             can_continue=True
    #             break
    #     if can_continue:
    #         continue
    #     for stream in streams:
    #         stream_len[stream]=0

    # for stream,length in stream_len.items():
    #     if length == 0:
    #         continue  
    #     if stream_ip_number[stream][0] in ip_domains_number:
    #         can_break=False
    #         for domain,numbers_dns in ip_domains_number[stream_ip_number[stream][0]].items():
    #             for number_dns in numbers_dns:
    #                 if 50 > stream_ip_number[stream][1]-number_dns > 0:  # 50个包以内就视为这个流的DNS查询
    #                     stream_len[stream]=0 
    #                 if can_break:
    #                     break
    #             if can_break:
    #                 break
    
    # for stream,length in stream_len.items():
    #     if length == 0:
    #         continue 

    #     num=stream_ip_number[stream][1]
    #     if number_informations[str(num)][0] not in src_ips:
    #         ip=number_informations[str(num)][0]
    #         port=number_informations[str(num)][2]
    #     else:
    #         ip=number_informations[str(num)][1]
    #         port=number_informations[str(num)][3]
    #     if ip not in other_ip_ports_filename_stream_length:
    #         other_ip_ports_filename_stream_length[ip]={}
    #         other_ip_ports_filename_stream_length[ip][port]={}
    #         other_ip_ports_filename_stream_length[ip][port][filename]={}
    #         other_ip_ports_filename_stream_length[ip][port][filename][stream]=length
    #     else:
    #         if port not in other_ip_ports_filename_stream_length[ip]:
    #             other_ip_ports_filename_stream_length[ip][port]={}
    #             other_ip_ports_filename_stream_length[ip][port][filename]={}
    #             other_ip_ports_filename_stream_length[ip][port][filename][stream]=length
    #         else:
    #             if filename not in other_ip_ports_filename_stream_length[ip][port]:
    #                 other_ip_ports_filename_stream_length[ip][port][filename]={}
    #                 other_ip_ports_filename_stream_length[ip][port][filename][stream]=length
    #             else:
    #                 other_ip_ports_filename_stream_length[ip][port][filename][stream]=length

    # write data
    output_txt=open('stat.txt', 'w')
    output_txt.write("所有来源文件:\n")
    for file_name in files_path:
        output_txt.write(file_name+"\n")
    output_txt.write("\n")
    output_txt.write("所有出现过的域名:\n")
    domain_number={}
    for domain,number_filename_stream_url_arr in domain_number_filename_stream_url.items():
        domain_number[domain]=number_filename_stream_url_arr[0]

    list_1=list(domain_number.items())
    domain_number_sort=dict(sorted(list_1,key=lambda x:x[1],reverse=True))
    
    for domain,number in domain_number_sort.items():
        output_txt.write(domain+","+str(number)+"\n")
    output_txt.write("\n含有关键字域名或url:\n")
    for domain,number_filename_stream_url_arr in domain_number_filename_stream_url.items():
        output_txt.write(domain+","+str(number_filename_stream_url_arr[0])+"\n")
        for filename,stream_url in number_filename_stream_url_arr[1].items():
            output_txt.write("\t"+filename+"\n")
            for stream,url in stream_url.items():
                output_txt.write("\t\t"+stream+","+url+"\n")
        output_txt.write("\n")
    output_txt.close()

    # output2_txt=open('stat2.txt', 'w')
    # output2_txt.write("所有来源文件:\n")
    # for file_name in files_path:
    #     output2_txt.write(file_name+"\n")
    # output2_txt.write("\nsensitive域名:\n")
    # for sensitive_domain,ports_filename_stream_length in sensitive_domain_ports_filename_stream_length.items():
    #     output2_txt.write("域名:"+sensitive_domain+"\n")
    #     for port,others in ports_filename_stream_length.items():
    #         output2_txt.write("\t"+port+"\n")
    #     output2_txt.write("\n")
    # output2_txt.close()

    output_stat={}
    output_stat['domain_number_filename_stream_url']=domain_number_filename_stream_url
    # output_stat['other_ip_ports_filename_stream_length']=other_ip_ports_filename_stream_length
    output_stat['files_path']=files_path
    
    output_json=open('stat.json','w')
    json.dump(output_stat, output_json)
    output_json.close()

def main():
    print("正在处理文件：",sys.argv[1])
    url_find(sys.argv[1],sys.argv)
    print("处理文件完成：",sys.argv[1])


if __name__ == "__main__":
    main()
