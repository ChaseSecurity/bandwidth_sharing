import json
import pyshark
import sys
import os.path
import time


def get_mail(file_name):
    json_file=open(file_name,'r')
    information_json=json.load(json_file)
    number_informations=information_json['number_informations']
    #base_time=information_json['base_time']
    filename=information_json['filename']
    #domain_ips=information_json['domain_ips']
    #ip_domains=information_json['ip_domains']
    stream_ip_number=information_json['stream_ip_number']
    #stream_timestamp=information_json['stream_timestamp']  #这个是有减去basetime的
    #domain_streams=information_json['domain_streams']
    stream_len=information_json['stream_len']
    ip_domains_number=information_json['ip_domains_number']
    #stream_numbers=information_json['stream_numbers']
    #all_len=information_json['all_len']
    all_base_tcp_len=information_json['all_base_tcp_len']

    stream_hosts={}
 

    files_path=[]
    domain_hour_length={}
    hour_lengh_domain_len_src={}
    hour_lengh_domain_len={}
    all__base_tcp_len=0
    src_domain_len=0
    other_len=0

    # init
    for i in range(24):
        hour_lengh_domain_len[str(i)]=[0,{}]
        hour_lengh_domain_len_src[str(i)]=[0,{}]
        
    # end init

    src_domains=['proxy.packetstream.io','api.packetstream.io','api.honeygain.com']
    src_ips=['172.19.0.2','172.19.0.3','172.19.0.4']
#0:src_ip  1:dst_ip     2:src_port    3:dst_port  4:length        5:stream       6:protocol    7:timestamp     8:host   9:_info


    #read old data
    try:
        input_json=open('stat.json','r')
        input_stat=json.load(input_json)
        domain_hour_length=input_stat['domain_hour_length']
        hour_lengh_domain_len_src=input_stat['hour_lengh_domain_len_src']
        hour_lengh_domain_len=input_stat['hour_lengh_domain_len']
        files_path=input_stat['files_path']
        all__base_tcp_len=input_stat['all__base_tcp_len']
        src_domain_len=input_stat['src_domain_len']
        other_len=input_stat['other_len']
        input_json.close()
    except:
        print("没有json文件")

    if os.path.basename(filename) in files_path:
        print("该文件已经被处理过，跳过处理！")
        return 
    files_path.append(os.path.basename(filename))
    files_path.sort()
    all__base_tcp_len+=all_base_tcp_len

    #deal with data
    for number,information in number_informations.items():
        if information[5] not in stream_hosts:
            stream_hosts[information[5]]=[]
            if information[8] != '' and information[8] not in stream_hosts[information[5]]:
                stream_hosts[information[5]].append(information[8])
        else:
            if information[8] != '' and information[8] not in stream_hosts[information[5]]:
                stream_hosts[information[5]].append(information[8])

    for stream,length in stream_len.items():
        if len(stream_hosts[stream]) !=0:
            continue    
        if stream_ip_number[stream][0] in ip_domains_number:
            can_break=False
            for domain,numbers_dns in ip_domains_number[stream_ip_number[stream][0]].items():
                for number_dns in numbers_dns:
                    if 50 > stream_ip_number[stream][1]-number_dns > 0:  # 50个包以内就视为这个流的DNS查询
                        # add domain
                        if domain not in stream_hosts[stream]:
                            stream_hosts[stream].append(domain)
                        can_break=True
                    if can_break:
                        break
                if can_break:
                    break
        if len(stream_hosts[stream]) ==0:
            if number_informations[str(stream_ip_number[stream][1])][0] not in src_ips:
                stream_hosts[stream].append(number_informations[str(stream_ip_number[stream][1])][0]+":"+number_informations[str(stream_ip_number[stream][1])][2])
            else:
                stream_hosts[stream].append(number_informations[str(stream_ip_number[stream][1])][1]+":"+number_informations[str(stream_ip_number[stream][1])][3])
    
    # time.localtime(int(float(now)))
    # time.struct_time(tm_year=2022, tm_mon=10, tm_mday=21, tm_hour=8, tm_min=31, tm_sec=20, tm_wday=4, tm_yday=294, tm_isdst=0)
    #4:length        5:stream       7:timestamp
    for number,information in number_informations.items():
        date_time=time.localtime(int(float(information[7])))
        hour=str(date_time.tm_hour)
        if stream_hosts[information[5]][0] not in src_domains:
            other_len+=information[4]
            hour_lengh_domain_len[hour][0]+=information[4]
            if stream_hosts[information[5]][0] not in hour_lengh_domain_len[hour][1]:
                hour_lengh_domain_len[hour][1][stream_hosts[information[5]][0]]=information[4]
            else:
                hour_lengh_domain_len[hour][1][stream_hosts[information[5]][0]]+=information[4]
        else:
            src_domain_len+=information[4]
            hour_lengh_domain_len_src[hour][0]+=information[4]
            if stream_hosts[information[5]][0] not in hour_lengh_domain_len_src[hour][1]:
                hour_lengh_domain_len_src[hour][1][stream_hosts[information[5]][0]]=information[4]
            else:
                hour_lengh_domain_len_src[hour][1][stream_hosts[information[5]][0]]+=information[4]

        if stream_hosts[information[5]][0] not in domain_hour_length:
            domain_hour_length[stream_hosts[information[5]][0]]={}
            for i in range(24):
                domain_hour_length[stream_hosts[information[5]][0]][str(i)]=0
            domain_hour_length[stream_hosts[information[5]][0]][hour]+=information[4]
        else:
            domain_hour_length[stream_hosts[information[5]][0]][hour]+=information[4]

   



    # write data

    output_txt=open('stat1.txt', 'w')
    output_txt.write("所有来源文件:\n")
    for file_name in files_path:
        output_txt.write(file_name+"\n")
    output_txt.write("\n")
    for hour,lenth_domain_len in hour_lengh_domain_len.items():
        output_txt.write("第"+hour+"时-第"+str(int(hour)+1)+"时:"+str(lenth_domain_len[0])+","+str(round(int(lenth_domain_len[0])*100.0/int(other_len),2))+"%\n")
        # for domain,length in lenth_domain_len[1].items():
        #     output_txt.write(domain+","+length+"\n")
        output_txt.write("\n")
    output_txt.write("\n\n\n")
    output_txt.write("="*100)
    output_txt.write("="*100)
    output_txt.write("\n\n\n")
    for hour,lenth_domain_len in hour_lengh_domain_len.items():
        output_txt.write("第"+hour+"时-第"+str(int(hour)+1)+"时:"+str(lenth_domain_len[0])+","+str(round(int(lenth_domain_len[0])*100.0/int(all__base_tcp_len),2))+"%\n")
        for domain,length in lenth_domain_len[1].items():
            output_txt.write(domain+","+str(length)+"\n")
        output_txt.write("\n")

    output_txt2=open('stat2.txt', 'w')
    output_txt2.write("所有来源文件:\n")
    for file_name in files_path:
        output_txt2.write(file_name+"\n")
    output_txt2.write("\n")
    for hour,lenth_domain_len in hour_lengh_domain_len_src.items():
        output_txt2.write("第"+hour+"时-第"+str(int(hour)+1)+"时:"+str(lenth_domain_len[0])+","+str(round(int(lenth_domain_len[0])*100.0/int(src_domain_len),2))+"%\n")
        output_txt2.write("\n")

    # output_txt4=open('stat4.txt', 'w')
    # output_txt4.write("所有来源文件:\n")
    # for file_name in files_path:
    #     output_txt4.write(file_name+"\n")
    # output_txt4.write("\n")
    # for hour,lenth_domain_len in hour_lengh_domain_len_all.items():
    #     output_txt4.write("第"+hour+"时-第"+str(int(hour)+1)+"时:"+str(lenth_domain_len[0])+","+str(round(int(lenth_domain_len[0])*100.0/int(all__base_tcp_len),2))+"%\n")
    #     output_txt4.write("\n")


    output_txt3=open('stat3.txt', 'w')
    output_txt3.write("所有来源文件:\n")
    for file_name in files_path:
        output_txt3.write(file_name+"\n")
    output_txt3.write("\n")

    for domain,hour_length in domain_hour_length.items():
        output_txt3.write(domain+"\n")
        all_length=0
        for hour,length in hour_length.items():
            all_length+=length
        for hour,length in hour_length.items():
            output_txt3.write("\t"+hour+","+str(length)+","+str(round(int(length)*100.0/int(all_length),2))+"%\n")
        output_txt3.write("\n")

    output_stat={}
    output_stat['domain_hour_length']=domain_hour_length
    output_stat['hour_lengh_domain_len_src']=hour_lengh_domain_len_src
    output_stat['hour_lengh_domain_len']=hour_lengh_domain_len
    output_stat['files_path']=files_path
    output_stat['all__base_tcp_len']=all__base_tcp_len
    output_stat['all__base_tcp_len']=all__base_tcp_len
    output_stat['src_domain_len']=src_domain_len
    output_stat['other_len']=other_len
    
    output_json=open('stat.json','w')
    json.dump(output_stat, output_json)
    output_json.close()

def main():
    print("正在处理文件：",sys.argv[1])
    get_mail(sys.argv[1])
    print("处理文件完成：",sys.argv[1])


if __name__ == "__main__":
    main()
