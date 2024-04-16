import json
import pyshark
import sys
import os.path


def get_domain_len(file_name):
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
    all_len=information_json['all_len']
    all_base_tcp_len=information_json['all_base_tcp_len']


    definded_traffic_len=0
    undefinded_traffic_len=0
    no_the_ip_traffic_len=0
    domain_len={}
    domain_len_rate={}
    files_path=[]
    #read old data
    try:
        input_json=open('stat.json','r')
        input_stat=json.load(input_json)
        all_len+=input_stat['all_len']
        all_base_tcp_len+=input_stat['all_base_tcp_len']
        definded_traffic_len=input_stat['definded_traffic_len']
        undefinded_traffic_len=input_stat['undefinded_traffic_len']
        no_the_ip_traffic_len=input_stat['no_the_ip_traffic_len']
        domain_len=input_stat['domain_len']
        files_path=input_stat['files_path']
        input_json.close()
    except:
        print("没有json文件")

    if os.path.basename(filename) in files_path:
        print("该文件已经被处理过，跳过处理！")
        return 
    files_path.append(os.path.basename(filename))
    files_path.sort()


        #deal with data --https and http
    for domain, streams in domain_streams.items():
        # if domain == 'www.macphoto.cn':
        #     print(streams)
        for stream in streams:
            if domain not in domain_len:
                domain_len[domain] = stream_len[stream]
                definded_traffic_len+=stream_len[stream]
                stream_len[stream]=0       
            else:
                domain_len[domain] += stream_len[stream]
                definded_traffic_len+=stream_len[stream]
                stream_len[stream]=0

    for stream,length in stream_len.items():
        if length == 0:
            continue   
        if stream_ip_number[stream][0] in ip_domains_number:
            can_break=False
            for domain,numbers_dns in ip_domains_number[stream_ip_number[stream][0]].items():
                for number_dns in numbers_dns:
                    if 50 > stream_ip_number[stream][1]-number_dns > 0:  # 50个包以内就视为这个流的DNS查询
                        # add length
                        if domain not in domain_len:
                            domain_len[domain] = stream_len[stream]
                            definded_traffic_len+=stream_len[stream]
                            stream_len[stream]=0       
                        else:
                            domain_len[domain] += stream_len[stream]
                            definded_traffic_len+=stream_len[stream]
                            stream_len[stream]=0 
                        can_break=True
                    if can_break:
                        break
                if can_break:
                    break

    for stream,length in stream_len.items():
        if length==0:
            continue
        if stream_ip_number[stream][0] not in ip_domains:
            no_the_ip_traffic_len+=length
        else:
            undefinded_traffic_len+=length
            count=len(ip_domains[stream_ip_number[stream][0]])
            for domain in ip_domains[stream_ip_number[stream][0]]:
                if domain not in domain_len:
                    domain_len[domain]=length/count
                else:
                    domain_len[domain]+=length/count

    # write data
    all_cal_traffic=definded_traffic_len+undefinded_traffic_len
    output_txt=open('stat.txt', 'w')
    output_txt.write("所有流量长度:"+str(all_len)+"\n")
    output_txt.write("所有TCP流量长度:"+str(all_base_tcp_len)+",占总流量比例:"+str(round(int(all_base_tcp_len)*100.0/int(all_len),2))+"%\n")
    output_txt.write("所有确定的TCP流量长度:"+str(definded_traffic_len)+",占总TCP流量比例:"+str(round(int(definded_traffic_len)*100.0/int(all_base_tcp_len),2))+"%\n")
    output_txt.write("所有不确定的TCP流量长度:"+str(undefinded_traffic_len)+",占总TCP流量比例:"+str(round(int(undefinded_traffic_len)*100.0/int(all_base_tcp_len),2))+"%\n")
    output_txt.write("只有ip地址没有域名的流量长度:"+str(no_the_ip_traffic_len)+",占总TCP流量比例:"+str(round(int(no_the_ip_traffic_len)*100.0/int(all_base_tcp_len),2))+"%\n\n")
    output_txt.write("所有来源文件:\n")
    for file_name in files_path:
        output_txt.write(file_name+"\n")
    output_txt.write("\n域名长度排序:\n")
    list_1 = list(domain_len.items())
    domain_len_sort= dict(sorted(list_1,key = lambda x:x[1],reverse= True))
    for domain,length in domain_len_sort.items():
        domain_len_rate[domain]=round(int(length)*100.0/all_cal_traffic,2)
        output_txt.write("域名:"+domain+",长度:"+str(round(length))+",占有比例:"+str(domain_len_rate[domain])+"%\n")
    output_txt.close()

    output_stat={}
    output_stat['all_len']=all_len
    output_stat['all_base_tcp_len']=all_base_tcp_len
    output_stat['definded_traffic_len']=definded_traffic_len
    output_stat['undefinded_traffic_len']=undefinded_traffic_len
    output_stat['no_the_ip_traffic_len']=no_the_ip_traffic_len
    output_stat['domain_len']=domain_len
    output_stat['domain_len_rate']=domain_len_rate
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
