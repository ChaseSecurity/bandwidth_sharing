import json
import dpkt
import sys
import os.path
import time
import socket
import struct

def unpacker(type_string, packet):
    """
    Returns network-order parsed data and the packet minus the parsed data.
    """
    if type_string.endswith('H'):
        length = 2
    if type_string.endswith('B'):
        length = 1
    if type_string.endswith('P'):  # 2 bytes for the length of the string
        length, packet = unpacker('H', packet)
        type_string = '{0}s'.format(length)
    if type_string.endswith('p'):  # 1 byte for the length of the string
        length, packet = unpacker('B', packet)
        type_string = '{0}s'.format(length)
    data = struct.unpack('!' + type_string, packet[:length])[0]
    if type_string.endswith('s'):
        #data = ''.join(data)
        data = data
    return data, packet[length:]

def get_one_hour(filename):

    stream_hosts={}
 

    files_path=[]
    domain_hour_length={}
    hour_lengh_domain_len_src={}
    hour_lengh_domain_len={}
    all_base_tcp_len=0
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
        all_base_tcp_len=input_stat['all_base_tcp_len']
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

    ip_domains_number={}
    ip_domains={}
    domain_ips={}
    stream_domain={}
    stream_ip_number_port={}

    stream_len={}

    stream_http_data={}

    stream_http=[]

    #当前stream号码
    stream_num=0
    #定义以172.19.0.2放在开头 '172.19.0.2_36450_172.67.74.242_443'--->[]
    ips_ports__stream_startN_startT_endN_endT={}
    stream_nums={}

    f=open(filename,'rb')
    
    pcap = dpkt.pcap.Reader(f)
    i=0    #当前pcap数据包 number



    for ts,buf in pcap:
        buf_length=len(buf)
        i+=1
    #make sure we are dealing with IP traffic
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except:
            continue
        if eth.type != 2048:
            continue

        ip = eth.data
        sip=socket.inet_ntoa(ip.src)
        dip=socket.inet_ntoa(ip.dst)

        
        #ip.src  ip.dst
        if ip.p == 17:
            protocol='udp'
            try:
                udp = ip.data
            except:
                continue
            try:
                dns = dpkt.dns.DNS(udp.data)
            except:
                continue
            sport=udp.sport
            dport=udp.dport
            if len(dns.qd)>0:
                # 有请求的域名
                qry_name=dns.qd[0].name
            if len(dns.an)>0:
                # 有回复
                for ans in dns.an:
                    try:  #不管cname
                        an_ip=socket.inet_ntoa(ans.ip)
                        
                        if an_ip not in ip_domains_number:
                            ip_domains_number[an_ip]={qry_name:[i]}  #i start with 1！
                        else:
                            if qry_name not in ip_domains_number[an_ip]:
                                ip_domains_number[an_ip][qry_name]=[i]
                            else:
                                ip_domains_number[an_ip][qry_name].append(i)
                        
                        if an_ip not in ip_domains:
                            ip_domains[an_ip] =[qry_name]
                        else:
                            if qry_name not in ip_domains[an_ip]:
                                ip_domains[an_ip].append(qry_name)
                        
                        if qry_name not in domain_ips:
                            domain_ips[qry_name]=[an_ip]
                        else:
                            if an_ip not in domain_ips[qry_name]:
                                domain_ips[qry_name].append(an_ip)
                    except:
                        continue
        elif ip.p==6:
            protocol='tcp'
            tcp= ip.data
            sport=tcp.sport
            dport=tcp.dport
            s_stream = tcp.data
            all_base_tcp_len+=buf_length
            host=''
            url=''
            is_http=False
            # 定义stream
            if sip not in src_ips:
                index=dip+"_"+str(dport)+"_"+sip+str(sport)
                if index not in ips_ports__stream_startN_startT_endN_endT:
                    ips_ports__stream_startN_startT_endN_endT[index]=[]
                    ips_ports__stream_startN_startT_endN_endT[index].append([stream_num,i,ts,i,ts])
                    stream=stream_num
                    stream_num+=1
                    
                else:
                    if ts-ips_ports__stream_startN_startT_endN_endT[index][len(ips_ports__stream_startN_startT_endN_endT[index])-1][4]<1800:
                        stream=ips_ports__stream_startN_startT_endN_endT[index][len(ips_ports__stream_startN_startT_endN_endT[index])-1][0]
                        ips_ports__stream_startN_startT_endN_endT[index][len(ips_ports__stream_startN_startT_endN_endT[index])-1][4]=ts
                        ips_ports__stream_startN_startT_endN_endT[index][len(ips_ports__stream_startN_startT_endN_endT[index])-1][3]=i
                    else:
                        stream=stream_num
                        ips_ports__stream_startN_startT_endN_endT[index].append([stream_num,i,ts,i,ts])
                        stream_num+=1
            else:
                index=sip+"_"+str(sport)+"_"+dip+str(dport)
                if index not in ips_ports__stream_startN_startT_endN_endT:
                    ips_ports__stream_startN_startT_endN_endT[index]=[]
                    ips_ports__stream_startN_startT_endN_endT[index].append([stream_num,i,ts,i,ts])
                    stream=stream_num
                    stream_num+=1
                    
                else:
                    if ts-ips_ports__stream_startN_startT_endN_endT[index][len(ips_ports__stream_startN_startT_endN_endT[index])-1][4]<1800:
                        stream=ips_ports__stream_startN_startT_endN_endT[index][len(ips_ports__stream_startN_startT_endN_endT[index])-1][0]
                        ips_ports__stream_startN_startT_endN_endT[index][len(ips_ports__stream_startN_startT_endN_endT[index])-1][4]=ts
                        ips_ports__stream_startN_startT_endN_endT[index][len(ips_ports__stream_startN_startT_endN_endT[index])-1][3]=i
                    else:
                        stream=stream_num
                        ips_ports__stream_startN_startT_endN_endT[index].append([stream_num,i,ts,i,ts])
                        stream_num+=1
            
            if len(s_stream) != 0:
                # continue
                if (s_stream[0]) in {20, 21, 22, 23}:
                    if (s_stream[0]) in {20, 21, 22}:
                        try:
                            records, bytes_used = dpkt.ssl.tls_multi_factory(s_stream)
                        
                            for record in records:
                                # if i==65206:
                                #     print(record)
                                if record.type == 22: #handshake

                                    data=record.data
                                    record_length=record.length
                                    total_len_consumed = 0
                                    while total_len_consumed < record_length:
                                        buffers = data[total_len_consumed:] 
                                        try:
                                            handshake = dpkt.ssl.TLSHandshake(buffers)
                                        except:
                                            handshake=''
                                            break
                                        
                                        
                                        total_len_consumed += handshake.length+ 4               
                                        if handshake.type == 1:
                                                
                                                payload = handshake.data.data
                                                
                                                session_id, payload = unpacker('p', payload)
                                                #ciper suite
                                                length=int.from_bytes(payload[0:2],byteorder="big")
                                                payload=payload[2+length:]
                                                
                                                #compression methods
                                                length=int.from_bytes(payload[0:1],byteorder="big")
                                                payload=payload[1+length:]                                    
                                                length=int.from_bytes(payload[0:2],byteorder="big")
                                                payload=payload[2:]
                                                
                                                now_len=0
                                                while now_len<length:
                                                    e_type=int.from_bytes(payload[0:2],byteorder="big")
                                                    payload=payload[2:]
                                                    e_length=int.from_bytes(payload[0:2],byteorder="big")
                                                    now_len+=e_length+4
                                                    payload=payload[2:]
                                                    if e_type==0:                                 
                                                        server_name_list_length=int.from_bytes(payload[0:2],byteorder="big")
                                                        payload=payload[2:]
                                                        server_name_type=int.from_bytes(payload[0:1],byteorder="big")
                                                        if server_name_type!=0:
                                                            print("错误0")
                                                        payload=payload[1:]
                                                        server_name_length=int.from_bytes(payload[0:2],byteorder="big")
                                                        payload=payload[2:]
                                                        host=payload[:server_name_length].decode()
                                                        
                                                    else:
                                                        payload=payload[e_length:]
                        except dpkt.ssl.SSL3Exception as exception:
                            pass
                else:
                    try:
                        ## 两个tcp合并怎么办，保存第一个，第二个开始计算
                        request = dpkt.http.Request(tcp.data)
                        stream_http_data[stream]=[tcp.data,[i]]
                        is_http=True
                        # url=request.uri
                        # host=request.headers.get('host')
                        # if host is None:
                        #     host=''
                        # 'http://'+request.headers['host']+request.uri
                    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                        if stream in stream_http_data and sip in src_ips:  #保证是本地发过去的第二个包
                            try:
                                request = dpkt.http.Request(stream_http_data[stream][0]+tcp.data)
                                url=request.uri
                                host=request.headers.get('host')
                                if host is None:
                                    host=''
                                del stream_http_data[stream] #删除缓存，同一条流可能有多个request
                            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):  #如果还缺数据，继续缓存
                                stream_http_data[stream][0]+=tcp.data
                                stream_http_data[stream][1].append(i)
                    
            if is_http:
                if stream not in stream_http:
                    stream_http.append(stream)
            
            if stream not in stream_nums:
                stream_nums[stream]=[i]
            else:
                stream_nums[stream].append(i)

            if stream not in stream_len:
                stream_len[stream]=buf_length
            else:
                stream_len[stream]+=buf_length

            if stream not in stream_domain:
                stream_domain[stream]=host
            else:
                if stream_domain[stream] == '':
                    stream_domain[stream]=host

            if stream not in stream_ip_number_port:
                if sip not in src_ips:
                    stream_ip_number_port[stream]=[sip,i,sport]
                else:
                    stream_ip_number_port[stream]=[dip,i,dport]

            
                

##还有剩下的一些缓存，尝试能不能转成host(即request后都是空tcp，就没办法使用缓存了)
    for stream, http_data in stream_http_data.items():
        try:
            request = dpkt.http.Request(http_data[0])
            url=request.uri
            host=request.headers.get('host')
            if host is None:
                host=''
            if stream not in stream_domain:
                stream_domain[stream]=host
            else:
                if stream_domain[stream] == '':
                    stream_domain[stream]=host
        except:
            pass

    #最后得到的sni会比原来的多，原因是会把重传的包的client hello算进去，但不影响。


    # 使用DNS确定域名
    for stream,domain_ in stream_domain.copy().items():
        if domain_!='':
            pass
        if stream_ip_number_port[stream][0] in ip_domains_number:
            can_break=False
            for domain,numbers_dns in ip_domains_number[stream_ip_number_port[stream][0]].items():
                for number_dns in numbers_dns:
                    if 200 > stream_ip_number_port[stream][1]-number_dns > 0:  # 200个包以内就视为这个流的DNS查询
                        stream_domain[stream]=domain
                        can_break=True
                    if can_break:
                        break
                if can_break:
                    break
   
    f.close()
    f=open(filename,'rb')
    pcap=dpkt.pcap.Reader(f)
    i=0
    stream_num=0
    ips_ports__stream_startN_startT_endN_endT.clear()
    for ts,buf in pcap:
        buf_length=len(buf)
        i+=1
    #make sure we are dealing with IP traffic
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except:
            continue
        if eth.type != 2048:
            continue

        ip = eth.data
        sip=socket.inet_ntoa(ip.src)
        dip=socket.inet_ntoa(ip.dst)

        
        #ip.src  ip.dst
        if ip.p == 17:
            continue
        elif ip.p==6:
            protocol='tcp'
            tcp= ip.data
            sport=tcp.sport
            dport=tcp.dport
            s_stream = tcp.data
            host=''
            url=''
            is_http=False
            # 定义stream
            if sip not in src_ips:
                index=dip+"_"+str(dport)+"_"+sip+str(sport)
                if index not in ips_ports__stream_startN_startT_endN_endT:
                    ips_ports__stream_startN_startT_endN_endT[index]=[]
                    ips_ports__stream_startN_startT_endN_endT[index].append([stream_num,i,ts,i,ts])
                    stream=stream_num
                    stream_num+=1
                    
                else:
                    if ts-ips_ports__stream_startN_startT_endN_endT[index][len(ips_ports__stream_startN_startT_endN_endT[index])-1][4]<1800:
                        stream=ips_ports__stream_startN_startT_endN_endT[index][len(ips_ports__stream_startN_startT_endN_endT[index])-1][0]
                        ips_ports__stream_startN_startT_endN_endT[index][len(ips_ports__stream_startN_startT_endN_endT[index])-1][4]=ts
                        ips_ports__stream_startN_startT_endN_endT[index][len(ips_ports__stream_startN_startT_endN_endT[index])-1][3]=i
                    else:
                        stream=stream_num
                        ips_ports__stream_startN_startT_endN_endT[index].append([stream_num,i,ts,i,ts])
                        stream_num+=1
            else:
                index=sip+"_"+str(sport)+"_"+dip+str(dport)
                if index not in ips_ports__stream_startN_startT_endN_endT:
                    ips_ports__stream_startN_startT_endN_endT[index]=[]
                    ips_ports__stream_startN_startT_endN_endT[index].append([stream_num,i,ts,i,ts])
                    stream=stream_num
                    stream_num+=1
                    
                else:
                    if ts-ips_ports__stream_startN_startT_endN_endT[index][len(ips_ports__stream_startN_startT_endN_endT[index])-1][4]<1800:
                        stream=ips_ports__stream_startN_startT_endN_endT[index][len(ips_ports__stream_startN_startT_endN_endT[index])-1][0]
                        ips_ports__stream_startN_startT_endN_endT[index][len(ips_ports__stream_startN_startT_endN_endT[index])-1][4]=ts
                        ips_ports__stream_startN_startT_endN_endT[index][len(ips_ports__stream_startN_startT_endN_endT[index])-1][3]=i
                    else:
                        stream=stream_num
                        ips_ports__stream_startN_startT_endN_endT[index].append([stream_num,i,ts,i,ts])
                        stream_num+=1
            date_time=time.localtime(int(float(ts)))
            hour=str(date_time.tm_hour)
            if stream_domain[stream] not in src_domains:
                other_len+=buf_length
                hour_lengh_domain_len[hour][0]+=buf_length
                if stream_domain[stream] not in hour_lengh_domain_len[hour][1]:
                    hour_lengh_domain_len[hour][1][stream_domain[stream]]=buf_length
                else:
                    hour_lengh_domain_len[hour][1][stream_domain[stream]]+=buf_length
            else:
                src_domain_len+=buf_length
                hour_lengh_domain_len_src[hour][0]+=buf_length
                if stream_domain[stream] not in hour_lengh_domain_len_src[hour][1]:
                    hour_lengh_domain_len_src[hour][1][stream_domain[stream]]=buf_length
                else:
                    hour_lengh_domain_len_src[hour][1][stream_domain[stream]]+=buf_length

            if stream_domain[stream] not in domain_hour_length:
                domain_hour_length[stream_domain[stream]]={}
                for j in range(24):
                    domain_hour_length[stream_domain[stream]][str(j)]=0
                domain_hour_length[stream_domain[stream]][hour]+=buf_length
            else:
                domain_hour_length[stream_domain[stream]][hour]+=buf_length


    output_stat={}
    output_stat['domain_hour_length']=domain_hour_length
    output_stat['hour_lengh_domain_len_src']=hour_lengh_domain_len_src
    output_stat['hour_lengh_domain_len']=hour_lengh_domain_len
    output_stat['files_path']=files_path
    output_stat['all_base_tcp_len']=all_base_tcp_len
    output_stat['src_domain_len']=src_domain_len
    output_stat['other_len']=other_len
    
    output_json=open('stat.json','w')
    json.dump(output_stat, output_json)
    output_json.close() 

def space():
    try:
        input_json=open('stat.json','r')
        input_stat=json.load(input_json)
        domain_hour_length=input_stat['domain_hour_length']
        hour_lengh_domain_len_src=input_stat['hour_lengh_domain_len_src']
        hour_lengh_domain_len=input_stat['hour_lengh_domain_len']
        files_path=input_stat['files_path']
        all_base_tcp_len=input_stat['all_base_tcp_len']
        src_domain_len=input_stat['src_domain_len']
        other_len=input_stat['other_len']
        input_json.close()
    except:
        print("没有json文件")
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
        output_txt.write("第"+hour+"时-第"+str(int(hour)+1)+"时:"+str(lenth_domain_len[0])+","+str(round(int(lenth_domain_len[0])*100.0/int(all_base_tcp_len),2))+"%\n")
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
    #     output_txt4.write("第"+hour+"时-第"+str(int(hour)+1)+"时:"+str(lenth_domain_len[0])+","+str(round(int(lenth_domain_len[0])*100.0/int(all_base_tcp_len),2))+"%\n")
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



def main():
    if len(sys.argv)==2:
        
        print("正在处理文件：",sys.argv[1])
        get_one_hour(sys.argv[1])
        print("处理文件完成：",sys.argv[1])
    elif len(sys.argv)==1:
        space()
    elif len(sys.argv)==3:
        if os.path.basename(sys.argv[1]).find(sys.argv[2])!=-1:
            print("正在处理文件：",sys.argv[1])
            get_one_hour(sys.argv[1])
            print("处理文件完成：",sys.argv[1])
        else:
            print("文件：",sys.argv[1],'未包含指定字符串：',sys.argv[2])
            return


if __name__ == "__main__":
    main()