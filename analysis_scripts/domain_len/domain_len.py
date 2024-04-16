import dpkt
import sys
import socket
import json
import struct
import os

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

def get_domain_len(filename):
    # filename=sys.argv[1]
    src_ips=['172.19.0.2','172.19.0.3','172.19.0.4']
    src_domains=['proxy.packetstream.io','api.packetstream.io','api.honeygain.com']


    number_information={}
    ip_domains_number={}
    ip_domains={}
    domain_ips={}

    stream_len={}
    stream_domain={}
    stream_ip_number={}

    stream_http_data={}


    #当前stream号码
    stream_num=0
    #定义以172.19.0.2放在开头 '172.19.0.2_36450_172.67.74.242_443'--->[]
    ips_ports__stream_startN_startT_endN_endT={}


    # 定义一个流的方法: src ip port,dst ip port, timestamp:后面的包跟前一个相差时间不超过半小时。1800s

    all_base_tcp_len=0
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
        all_base_tcp_len=input_stat['all_base_tcp_len']
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
        exit()
    files_path.append(os.path.basename(filename))
    files_path.sort()
    

    
    f=open(filename,'rb')
    pcap = dpkt.pcap.Reader(f)
    all_i=[]
    all_len=0
    i=0



    for ts,buf in pcap:
        buf_length=len(buf)
        all_len+=buf_length
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
            try:
                udp = ip.data
            except:
                continue
            try:
                dns = dpkt.dns.DNS(udp.data)
            except:
                continue
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
            tcp= ip.data
            all_base_tcp_len+=buf_length
            sport=tcp.sport
            dport=tcp.dport
            s_stream = tcp.data
            host=''
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
                        request = dpkt.http.Request(tcp.data)
                        stream_http_data[stream]=[tcp.data,[i]]
                        
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
                
                 
            #统计长度
            if stream not in stream_len:
                stream_len[stream]=buf_length
            else:
                stream_len[stream]+=buf_length

            if stream not in stream_domain:
                stream_domain[stream]=host
            else:
                if stream_domain[stream] == '':
                    stream_domain[stream]=host

            if stream not in stream_ip_number:
                if sip not in src_ips:
                    stream_ip_number[stream]=[sip,i]
                else:
                    stream_ip_number[stream]=[dip,i]
            




    for stream,domain_ in stream_domain.items():
        if domain_!='':
            if domain_ not in domain_len:
                domain_len[domain_] = stream_len[stream]
                definded_traffic_len+=stream_len[stream]
                stream_len[stream]=0  
            else:
                domain_len[domain_] += stream_len[stream]
                definded_traffic_len+=stream_len[stream]
                stream_len[stream]=0 
        if stream_ip_number[stream][0] in ip_domains_number:
            can_break=False
            for domain,numbers_dns in ip_domains_number[stream_ip_number[stream][0]].items():
                for number_dns in numbers_dns:
                    if 200 > stream_ip_number[stream][1]-number_dns > 0: 
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

    output_stat={}
    # output_stat['all_len']=all_len
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

def space():
    #read old data
    try:
        input_json=open('stat.json','r')
        input_stat=json.load(input_json)
        all_base_tcp_len=input_stat['all_base_tcp_len']
        definded_traffic_len=input_stat['definded_traffic_len']
        undefinded_traffic_len=input_stat['undefinded_traffic_len']
        no_the_ip_traffic_len=input_stat['no_the_ip_traffic_len']
        domain_len=input_stat['domain_len']
        files_path=input_stat['files_path']
        input_json.close()
    except:
        print("没有json文件")
        return
    # write data
    all_cal_traffic=definded_traffic_len+undefinded_traffic_len
    output_txt=open('stat.txt', 'w')
    output_txt.write("所有TCP流量长度:"+str(all_base_tcp_len)+"\n")
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
        # domain_len_rate[domain]=round(int(length)*100.0/all_cal_traffic,2)
        output_txt.write("域名:"+str(domain)+",长度:"+str(round(length))+",占有比例:"+str(round(int(length)*100.0/all_cal_traffic,2))+"%\n")
    output_txt.close()

    


def main():
    if len(sys.argv)==2:
        print('正在处理文件:',sys.argv[1])
        get_domain_len(sys.argv[1])
        print('处理文件完成:',sys.argv[1])
    elif len(sys.argv)==3:
        if sys.argv[1].find(sys.argv[2])!=-1:
            print('正在处理文件:',sys.argv[1])
            get_domain_len(sys.argv[1])
            print('处理文件完成:',sys.argv[1])
        else:
            print('文件:',sys.argv[1]," 未包含字符串:",sys.argv[2])
    elif len(sys.argv)==1:
        space()

if __name__ == "__main__":
    main()
