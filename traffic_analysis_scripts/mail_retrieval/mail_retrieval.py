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

    tcp_stream_len={}
    stream_num=0

    #当前stream号码
    tcp_stream_num=0
    #定义以172.19.0.2放在开头 '172.19.0.2_36450_172.67.74.242_443'--->[]
    tcp_ips_ports__stream_startN_startT_endN_endT={}

    udp_stream_len={}
    
    all_len=0
    all_tcp_len=0
    all_udp_len=0


    udp_port_filename_ip_len_number={}

    tcp_stream_ip_port={}
    udp_stream_ip_port={}

    tcp_stream_len={}
    udp_stream_len={}

    stream_http_data={}
    stream_domain={}
    
    # 定义一个流的方法: src ip port,dst ip port, timestamp:后面的包跟前一个相差时间不超过半小时。1800s
    port_filename_stream_ip_host_length_contents={}
    files_path=[]
    #read old data
    try:
        input_json=open('stat.json','r')
        input_stat=json.load(input_json)
        port_filename_stream_ip_host_length_contents=input_stat['port_filename_stream_ip_host_length_contents']
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
    i=0

    need_port=[143,110,993,995,109,'143','110','993','995','109']
    stream_contents={}

    for ts,buf in pcap:
        i+=1
        buf_len=len(buf)
        all_len+=buf_len
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
            udp=ip.data
            all_udp_len+=buf_len
            try:
                sport=udp.sport
                dport=udp.dport
            except:
                continue
            
            if sip not in src_ips:
                stream=dip+"_"+str(dport)+"_"+sip+str(sport)
            else:
                stream=sip+"_"+str(sport)+"_"+dip+str(dport)
            
            if stream not in udp_stream_ip_port:
                if sip not in src_ips:
                    udp_stream_ip_port[stream]=[sip,sport]
                else:
                    udp_stream_ip_port[stream]=[dip,dport]
                
            if stream not in udp_stream_len:
                udp_stream_len[stream]=buf_len
            else:
                udp_stream_len[stream]+=buf_len
                
        elif ip.p==6:
            all_tcp_len+=buf_len
            tcp= ip.data
            host=''
            try:
                sport=tcp.sport
                dport=tcp.dport
            except:
                continue
            # s_stream = tcp.data
            
            # host=''
            # # 定义stream
            if sip not in src_ips:
                index=dip+"_"+str(dport)+"_"+sip+str(sport)
                if index not in tcp_ips_ports__stream_startN_startT_endN_endT:
                    tcp_ips_ports__stream_startN_startT_endN_endT[index]=[]
                    tcp_ips_ports__stream_startN_startT_endN_endT[index].append([stream_num,i,ts,i,ts,False])
                    stream=str(stream_num)
                    stream_num+=1
                    if tcp.flags !=2: #文件开头未完整的流也被定义未一个新的流
                        tcp_ips_ports__stream_startN_startT_endN_endT[index][len(tcp_ips_ports__stream_startN_startT_endN_endT[index])-1][5]=True
                    
                else:
                    if tcp.flags!=2:  #不是syn，就是这个ip_port的最后一个流号码
                        stream=tcp_ips_ports__stream_startN_startT_endN_endT[index][len(tcp_ips_ports__stream_startN_startT_endN_endT[index])-1][0]
                        tcp_ips_ports__stream_startN_startT_endN_endT[index][len(tcp_ips_ports__stream_startN_startT_endN_endT[index])-1][4]=ts
                        tcp_ips_ports__stream_startN_startT_endN_endT[index][len(tcp_ips_ports__stream_startN_startT_endN_endT[index])-1][3]=i
                        tcp_ips_ports__stream_startN_startT_endN_endT[index][len(tcp_ips_ports__stream_startN_startT_endN_endT[index])-1][5]=True
                    else: #如果遇到新的syn，分配新的流号码
                        stream=str(stream_num)
                        tcp_ips_ports__stream_startN_startT_endN_endT[index].append([stream_num,i,ts,i,ts,False])
                        stream_num+=1
            else:
                index=sip+"_"+str(sport)+"_"+dip+str(dport)
                if index not in tcp_ips_ports__stream_startN_startT_endN_endT:
                    tcp_ips_ports__stream_startN_startT_endN_endT[index]=[]
                    tcp_ips_ports__stream_startN_startT_endN_endT[index].append([stream_num,i,ts,i,ts,False])
                    stream=str(stream_num)
                    stream_num+=1
                    if tcp.flags !=2:
                        tcp_ips_ports__stream_startN_startT_endN_endT[index][len(tcp_ips_ports__stream_startN_startT_endN_endT[index])-1][5]=True
                    
                else:
                    if tcp.flags!=2:
                        stream=tcp_ips_ports__stream_startN_startT_endN_endT[index][len(tcp_ips_ports__stream_startN_startT_endN_endT[index])-1][0]
                        tcp_ips_ports__stream_startN_startT_endN_endT[index][len(tcp_ips_ports__stream_startN_startT_endN_endT[index])-1][4]=ts
                        tcp_ips_ports__stream_startN_startT_endN_endT[index][len(tcp_ips_ports__stream_startN_startT_endN_endT[index])-1][3]=i
                        tcp_ips_ports__stream_startN_startT_endN_endT[index][len(tcp_ips_ports__stream_startN_startT_endN_endT[index])-1][5]=True
                    else:
                        stream=str(stream_num)
                        tcp_ips_ports__stream_startN_startT_endN_endT[index].append([stream_num,i,ts,i,ts,False])
                        stream_num+=1
            
            s_stream = tcp.data
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
                        
                    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                        if stream in stream_http_data and sip in src_ips:  #保证是本地发过去的第二个包
                            try:
                                request = dpkt.http.Request(stream_http_data[stream][0]+tcp.data)
                                url=request.uri
                                host=request.headers.get('host')
                                if host is None:
                                    host=''
                                del stream_http_data[stream] #删除缓存，同一条流可能有多个request
                            except :  #如果还缺数据，继续缓存
                                stream_http_data[stream][0]+=tcp.data
                                stream_http_data[stream][1].append(i)
               

            if stream not in tcp_stream_ip_port:
                if sip not in src_ips:
                    tcp_stream_ip_port[stream]=[sip,sport]
                    
                else:
                    tcp_stream_ip_port[stream]=[dip,dport]
                
            if stream not in tcp_stream_len:
                tcp_stream_len[stream]=buf_len
            else:
                tcp_stream_len[stream]+=buf_len

            content=str(tcp.data)[2:-1]
            if sip not in src_ips and sport in need_port:
                if stream not in stream_contents:
                    stream_contents[stream]=[content]
                else:
                    stream_contents[stream].append(content)
            elif sip in src_ips and dport in need_port:
                if stream not in stream_contents:
                    stream_contents[stream]=[content]
                else:
                    stream_contents[stream].append(content)

            if stream not in stream_domain:
                stream_domain[stream]=host
            else:
                if stream_domain[stream] == '':
                    stream_domain[stream]=host
    
    file_name=os.path.basename(filename) 
    for stream,ip_port in udp_stream_ip_port.items():
        ip=ip_port[0]
        port=str(ip_port[1])
        if  port not in udp_port_filename_ip_len_number:
            udp_port_filename_ip_len_number[port]={}
            if file_name not in  udp_port_filename_ip_len_number[port]:
                udp_port_filename_ip_len_number[port][file_name]={}
                if ip not in udp_port_filename_ip_len_number[port][file_name]:
                    udp_port_filename_ip_len_number[port][file_name][ip]=[udp_stream_len[stream],1]
                else:
                    udp_port_filename_ip_len_number[port][file_name][ip][0]+=udp_stream_len[stream]
                    udp_port_filename_ip_len_number[port][file_name][ip][1]+=1
            else:
                if ip not in udp_port_filename_ip_len_number[port][file_name]:
                    udp_port_filename_ip_len_number[port][file_name][ip]=[udp_stream_len[stream],1]
                else:
                    udp_port_filename_ip_len_number[port][file_name][ip][0]+=udp_stream_len[stream]
                    udp_port_filename_ip_len_number[port][file_name][ip][1]+=1
        else:
            if file_name not in  udp_port_filename_ip_len_number[port]:
                udp_port_filename_ip_len_number[port][file_name]={}
                if ip not in udp_port_filename_ip_len_number[port][file_name]:
                    udp_port_filename_ip_len_number[port][file_name][ip]=[udp_stream_len[stream],1]
                else:
                    udp_port_filename_ip_len_number[port][file_name][ip][0]+=udp_stream_len[stream]
                    udp_port_filename_ip_len_number[port][file_name][ip][1]+=1
            else:
                if ip not in udp_port_filename_ip_len_number[port][file_name]:
                    udp_port_filename_ip_len_number[port][file_name][ip]=[udp_stream_len[stream],1]
                else:
                    udp_port_filename_ip_len_number[port][file_name][ip][0]+=udp_stream_len[stream]
                    udp_port_filename_ip_len_number[port][file_name][ip][1]+=1


    

    for stream,ip_port in tcp_stream_ip_port.items():
        ip=ip_port[0]
        port=str(ip_port[1])
        if  port  in need_port:
            if port not in port_filename_stream_ip_host_length_contents:
                port_filename_stream_ip_host_length_contents[port]={}
                port_filename_stream_ip_host_length_contents[port][file_name]={}
                port_filename_stream_ip_host_length_contents[port][file_name][stream]=[ip,stream_domain[stream],tcp_stream_len[stream],stream_contents[stream]]
            else:
                if file_name not in port_filename_stream_ip_host_length_contents[port]:
                    port_filename_stream_ip_host_length_contents[port][file_name]={}
                    port_filename_stream_ip_host_length_contents[port][file_name][stream]=[ip,stream_domain[stream],tcp_stream_len[stream],stream_contents[stream]]
                else:
                    port_filename_stream_ip_host_length_contents[port][file_name][stream]=[ip,stream_domain[stream],tcp_stream_len[stream],stream_contents[stream]]
    # print(tcp_stream_ip_port)

    

    output_stat={}
    output_stat['port_filename_stream_ip_host_length_contents']=port_filename_stream_ip_host_length_contents
    output_stat['files_path']=files_path

    output_json=open('stat.json','w')
    json.dump(output_stat, output_json)
    output_json.close()

def space(port_list):
    port_list=port_list[1:]
    #read old data
    try:
        input_json=open('stat.json','r')
        input_stat=json.load(input_json)
        port_filename_stream_ip_host_length_contents=input_stat['port_filename_stream_ip_host_length_contents']
        files_path=input_stat['files_path']
        input_json.close()
    except:
        print("没有json文件")
    
    all_domain=open('all_domain.txt','w')
    contents_file=open('contens.txt','w')
    for port,filename_stream_ip_host_length_contents in port_filename_stream_ip_host_length_contents.items():
        # '143','110','993','995','109'
        # print(port)
        if port not in  port_list:
            # print('no')
            continue
        for filename,stream_ip_host_length_contents in filename_stream_ip_host_length_contents.items():
            for stream,ip_host_length_contents in stream_ip_host_length_contents.items():
                if ip_host_length_contents[1]!='':
                    all_domain.write(ip_host_length_contents[1]+"\n")
                
                # contents_file.write(str(ip_host_length_contents[3])+"\n"*3)
                contents=""
                for content in ip_host_length_contents[3]:
                    content=content.replace('\\r\\n','\n')
                    contents+=content
                    # contents_file.write(content)

                
                if contents.strip()!='':
                    contents_file.write(filename+"\n")
                    contents_file.write(stream+","+str(ip_host_length_contents[0])+"\n")
                    contents_file.write(contents)
                    contents_file.write('\n'*3)

                
def main(): 

    space(sys.argv)

if __name__ == "__main__":
    main()
 