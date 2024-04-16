import json
import pyshark
import sys
import os.path


def get_time(file_name):
    #file_name='/home/hrh/bandwidth_sharing/traffic_stats/v6_stat_program/honeygain_vps5_2022-09-13_17-12-27.pcap_v2.json'

    json_file=open(file_name,'r')
    information_json=json.load(json_file)
    #number_informations=information_json['number_informations']
    base_time=information_json['base_time']
    filename=information_json['filename']
    #domain_ips=information_json['domain_ips']
    #ip_domains=information_json['ip_domains']
    #stream_ip_number=information_json['stream_ip_number']
    stream_timestamp=information_json['stream_timestamp']
    domain_streams=information_json['domain_streams']
    #stream_len=information_json['stream_len']
    #ip_domains_number=information_json['ip_domains_number']
    #stream_numbers=information_json['stream_numbers']
    #all_len=information_json['all_len']
    #all_base_tcp_len=information_json['all_base_tcp_len']


    files_path=[]

    src_domains=['proxy.packetstream.io','api.packetstream.io']
    time_domains_streams=[ {} for _ in range(24*60*2+1)]  #每半分钟每种域名对应的请求次数，+1防止溢出
    domain__filename_timeGap_stream_time={}
    filename_timeGap_domain_stream_time={}

    #read old data
    try:
        input_json=open('time.json','r')
        input_stat=json.load(input_json)
        domain__filename_timeGap_stream_time=input_stat['domain__filename_timeGap_stream_time']
        filename_timeGap_domain_stream_time=input_stat['filename_timeGap_domain_stream_time']
        files_path=input_stat['files_path']
        input_json.close()
    except:
        print("没有json文件")

    if os.path.basename(filename) in files_path:
        print("该文件已经被处理过，跳过处理！")
        return 
    files_path.append(os.path.basename(filename))
    files_path.sort()

        #deal with time
    for domain, streams in domain_streams.items():
        for stream in streams:
            if domain not in time_domains_streams[int(stream_timestamp[stream]/30)]:
                time_domains_streams[int(stream_timestamp[stream]/30)][domain]=[stream]
            else:
                time_domains_streams[int(stream_timestamp[stream]/30)][domain].append(stream)
        
        # for stream,numbers in stream_numbers.items():
        #     for number in numbers:
        #         print(int((float(number_informations[number][7])-base_time)))
        #         if number_informations[number][8] not in time_domains_length[int((float(number_informations[number][7])-base_time)/30)]:
        #             time_domains_length[int((float(number_informations[number][7])-base_time)/30)][number_informations[number][8]]=number_informations[number][4]
        #         else:
        #             time_domains_length[int((float(number_informations[number][7])-base_time)/30)][number_informations[number][8]]+=number_informations[number][4]

    # time_output=open('time_output.txt', 'a+')
    # time_output.write(os.path.basename(filename)+"\n")
    # time_output.write("="*30+"\n")
    # can_print=True
    filename_timeGap_domain_stream_time[filename]={}
    for i in range(len(time_domains_streams)-2):
        # if not can_print:
        #     time_output.write("="*30+"\n")
        # can_print=True
        next_domains_streams=time_domains_streams[i+1]
        for domain,streams in time_domains_streams[i].items():
            num=len(streams)
            if domain in src_domains:
                continue
            if domain in next_domains_streams:
                next_number=len(next_domains_streams[domain])
            else:
                next_number=0
            if num+next_number >=10 : #一分钟超过10次请求
                # 
                if domain not in domain__filename_timeGap_stream_time:
                    domain__filename_timeGap_stream_time[domain]={}
                    domain__filename_timeGap_stream_time[domain][filename]={}
                    domain__filename_timeGap_stream_time[domain][filename]["第{"+str(i/2)+"-"+str(i/2+0.5)+"}分钟"]={}
                    domain__filename_timeGap_stream_time[domain][filename]["第{"+str(i/2+0.5)+"-"+str(i/2+1)+"}分钟"]={}
                    for stream in streams:
                        domain__filename_timeGap_stream_time[domain][filename]["第{"+str(i/2)+"-"+str(i/2+0.5)+"}分钟"][stream]=stream_timestamp[stream]+base_time
                    if domain in next_domains_streams:
                        for stream in next_domains_streams[domain]:
                            domain__filename_timeGap_stream_time[domain][filename]["第{"+str(i/2+0.5)+"-"+str(i/2+1)+"}分钟"][stream]=stream_timestamp[stream]+base_time
                else:
                    if filename not in domain__filename_timeGap_stream_time[domain]:
                        domain__filename_timeGap_stream_time[domain][filename]={}
                        domain__filename_timeGap_stream_time[domain][filename]["第{"+str(i/2)+"-"+str(i/2+0.5)+"}分钟"]={}
                        domain__filename_timeGap_stream_time[domain][filename]["第{"+str(i/2+0.5)+"-"+str(i/2+1)+"}分钟"]={}
                        for stream in streams:
                            domain__filename_timeGap_stream_time[domain][filename]["第{"+str(i/2)+"-"+str(i/2+0.5)+"}分钟"][stream]=stream_timestamp[stream]+base_time
                        if domain in next_domains_streams:
                            for stream in next_domains_streams[domain]:
                                domain__filename_timeGap_stream_time[domain][filename]["第{"+str(i/2+0.5)+"-"+str(i/2+1)+"}分钟"][stream]=stream_timestamp[stream]+base_time
                    else:
                        domain__filename_timeGap_stream_time[domain][filename]["第{"+str(i/2)+"-"+str(i/2+0.5)+"}分钟"]={}
                        domain__filename_timeGap_stream_time[domain][filename]["第{"+str(i/2+0.5)+"-"+str(i/2+1)+"}分钟"]={}
                        for stream in streams:
                            domain__filename_timeGap_stream_time[domain][filename]["第{"+str(i/2)+"-"+str(i/2+0.5)+"}分钟"][stream]=stream_timestamp[stream]+base_time
                        if domain in next_domains_streams:
                            for stream in next_domains_streams[domain]:
                                domain__filename_timeGap_stream_time[domain][filename]["第{"+str(i/2+0.5)+"-"+str(i/2+1)+"}分钟"][stream]=stream_timestamp[stream]+base_time

                #
                if "第{"+str(i/2)+"-"+str(i/2+0.5)+"}分钟" not in filename_timeGap_domain_stream_time[filename]:
                    filename_timeGap_domain_stream_time[filename]["第{"+str(i/2)+"-"+str(i/2+0.5)+"}分钟"]={}
                    filename_timeGap_domain_stream_time[filename]["第{"+str(i/2)+"-"+str(i/2+0.5)+"}分钟"][domain]={}
                    for stream in streams:
                        filename_timeGap_domain_stream_time[filename]["第{"+str(i/2)+"-"+str(i/2+0.5)+"}分钟"][domain][stream]=stream_timestamp[stream]+base_time
                else:
                    filename_timeGap_domain_stream_time[filename]["第{"+str(i/2)+"-"+str(i/2+0.5)+"}分钟"][domain]={}
                    for stream in streams:
                        filename_timeGap_domain_stream_time[filename]["第{"+str(i/2)+"-"+str(i/2+0.5)+"}分钟"][domain][stream]=stream_timestamp[stream]+base_time
                
                if "第{"+str(i/2+0.5)+"-"+str(i/2+1)+"}分钟" not in filename_timeGap_domain_stream_time[filename]:
                    filename_timeGap_domain_stream_time[filename]["第{"+str(i/2+0.5)+"-"+str(i/2+1)+"}分钟"]={}
                    filename_timeGap_domain_stream_time[filename]["第{"+str(i/2+0.5)+"-"+str(i/2+1)+"}分钟"][domain]={}
                    if domain in next_domains_streams:
                        for stream in next_domains_streams[domain]:
                            filename_timeGap_domain_stream_time[filename]["第{"+str(i/2+0.5)+"-"+str(i/2+1)+"}分钟"][domain][stream]=stream_timestamp[stream]+base_time   
                else:
                    filename_timeGap_domain_stream_time[filename]["第{"+str(i/2+0.5)+"-"+str(i/2+1)+"}分钟"][domain]={}
                    if domain in next_domains_streams:
                        for stream in next_domains_streams[domain]:
                            filename_timeGap_domain_stream_time[filename]["第{"+str(i/2+0.5)+"-"+str(i/2+1)+"}分钟"][domain][stream]=stream_timestamp[stream]+base_time    
            elif num>=5:
                if domain not in domain__filename_timeGap_stream_time:
                    domain__filename_timeGap_stream_time[domain]={}
                    domain__filename_timeGap_stream_time[domain][filename]={}
                    domain__filename_timeGap_stream_time[domain][filename]["第{"+str(i/2)+"-"+str(i/2+0.5)+"}分钟"]={}
                    for stream in streams:
                        domain__filename_timeGap_stream_time[domain][filename]["第{"+str(i/2)+"-"+str(i/2+0.5)+"}分钟"][stream]=stream_timestamp[stream]+base_time                    
                else:
                    if filename not in domain__filename_timeGap_stream_time[domain]:
                        domain__filename_timeGap_stream_time[domain][filename]={}
                        domain__filename_timeGap_stream_time[domain][filename]["第{"+str(i/2)+"-"+str(i/2+0.5)+"}分钟"]={}                        
                        for stream in streams:
                            domain__filename_timeGap_stream_time[domain][filename]["第{"+str(i/2)+"-"+str(i/2+0.5)+"}分钟"][stream]=stream_timestamp[stream]+base_time            
                    else:
                        if "第{"+str(i/2)+"-"+str(i/2+0.5)+"}分钟" not in domain__filename_timeGap_stream_time[domain][filename]:
                            domain__filename_timeGap_stream_time[domain][filename]["第{"+str(i/2)+"-"+str(i/2+0.5)+"}分钟"]={}
                            for stream in streams:
                                domain__filename_timeGap_stream_time[domain][filename]["第{"+str(i/2)+"-"+str(i/2+0.5)+"}分钟"][stream]=stream_timestamp[stream]+base_time
                        

                #
                if "第{"+str(i/2)+"-"+str(i/2+0.5)+"}分钟" not in filename_timeGap_domain_stream_time[filename]:
                    filename_timeGap_domain_stream_time[filename]["第{"+str(i/2)+"-"+str(i/2+0.5)+"}分钟"]={}
                    filename_timeGap_domain_stream_time[filename]["第{"+str(i/2)+"-"+str(i/2+0.5)+"}分钟"][domain]={}
                    for stream in streams:
                        filename_timeGap_domain_stream_time[filename]["第{"+str(i/2)+"-"+str(i/2+0.5)+"}分钟"][domain][stream]=stream_timestamp[stream]+base_time
                else:
                    if domain not in filename_timeGap_domain_stream_time[filename]["第{"+str(i/2)+"-"+str(i/2+0.5)+"}分钟"]:
                        filename_timeGap_domain_stream_time[filename]["第{"+str(i/2)+"-"+str(i/2+0.5)+"}分钟"][domain]={}
                        for stream in streams:
                            filename_timeGap_domain_stream_time[filename]["第{"+str(i/2)+"-"+str(i/2+0.5)+"}分钟"][domain][stream]=stream_timestamp[stream]+base_time
                
        #         if can_print:
        #             time_output.write("第{"+str(i/2)+"-"+str(i/2+1)+"}分钟\n")
        #             can_print=False
        #         time_output.write(domain+","+str(num+next_number)+"\n")
        # if not can_print:
        #     time_output.write("="*30+"\n")
    # time_output.write("="*30+"\n\n")
    # time_output.close()

    # time_output_2=open('time_output_2.txt', 'a+')
    # time_output_2.write(os.path.basename(filename)+"\n")
    # time_output_2.write("="*30+"\n")
    # can_print=True
    # for i in range(len(time_domains_length)-2):
    #     if not can_print:
    #         time_output_2.write("="*30+"\n")
    #     can_print=True
    #     next_domains_length=time_domains_length[i+1]
    #     for domain,length in time_domains_length[i].items():
    #         if domain in src_domains:
    #             continue
    #         if domain in next_domains_length:
    #             next_length=next_domains_length[domain]
    #         else:
    #             next_length=0
    #         if length+next_length > 5000 : #一分钟超过100000B
    #             if can_print:
    #                 time_output_2.write("第{"+str(i/2)+"-"+str(i/2+1)+"}分钟\n")
    #                 can_print=False
    #             time_output_2.write(domain+","+str(length+next_length)+"\n")
    #     if not can_print:
    #         time_output_2.write("="*30+"\n")
    # time_output_2.write("="*30+"\n\n")
    # time_output_2.close()


    time_txt=open('time.txt','w')
    for domain,filename_timegGap_stream_time in domain__filename_timeGap_stream_time.items():
        time_txt.write(domain+"\n")
        for filename,timeGap_stream_time in filename_timegGap_stream_time.items():
            time_txt.write("\t"+filename+"\n")
            for timeGap,stream_time in timeGap_stream_time.items():
                time_txt.write("\t\t"+timeGap+","+str(len(stream_time))+"\n")
                list_1 = list(stream_time.items())
                stream_time_sort= dict(sorted(list_1,key = lambda x:x[1]))
                for stream,time in stream_time_sort.items():
                    time_txt.write("\t\t\t"+str(stream)+","+str(time)+"\n")
        time_txt.write("\n")
    time_txt.close()

    time2_txt=open('time2.txt','w')
    for filename,timeGap_domain_stream_time in filename_timeGap_domain_stream_time.items():
        time2_txt.write(filename+"\n")
        for timeGap,domain_stream_time in timeGap_domain_stream_time.items():
            time2_txt.write("\t"+timeGap+"\n")
            for domain,stream_time in domain_stream_time.items():
                time2_txt.write("\t\t"+domain+","+str(len(stream_time))+"\n")
                list_1 = list(stream_time.items())
                stream_time_sort= dict(sorted(list_1,key = lambda x:x[1]))
                for stream,time in stream_time_sort.items():
                    time2_txt.write("\t\t\t"+str(stream)+","+str(time)+"\n")
        time2_txt.write("\n")
    time2_txt.close()
    # write data
    output_stat={}
    output_stat['domain__filename_timeGap_stream_time']=domain__filename_timeGap_stream_time
    output_stat['filename_timeGap_domain_stream_time']=filename_timeGap_domain_stream_time
    output_stat['files_path']=files_path
    
    output_json=open('time.json','w')
    json.dump(output_stat, output_json)
    output_json.close()

def main():
    print("正在处理文件：",sys.argv[1])
    get_time(sys.argv[1])
    print("处理文件完成：",sys.argv[1])


if __name__ == "__main__":
    main()
