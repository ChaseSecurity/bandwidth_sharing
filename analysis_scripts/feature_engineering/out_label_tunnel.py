import dpkt
import sys
import socket
import json
import struct
import os

out_packet_dir='./packet/'
out_flow_dir='./flow/'

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

def out_label_packetstream_tunnel(filename):
    # filename=sys.argv[1]

    src_ips=['172.19.0.2','172.19.0.3','172.19.0.4']
    src_domains=['proxy.packetstream.io']


    number_information={}

    # 处理DNS所需要的变量
    ip_domains_number={}
    ip_domains={}
    domain_ips={}
    stream_domain={}
    stream_ip_number={}

    stream_http_data={}

    #当前stream号码
    stream_num=0
    #定义以172.19.0.2放在开头 '172.19.0.2_36450_172.67.74.242_443'--->[]
    ips_ports__stream_startN_startT_endN_endT={}
    # 定义一个流的方法: src ip port,dst ip port, timestamp:后面的包跟第一个相差时间不超过半小时则视为同一条流。1800s
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
            information=[sip,sport,dip,dport,ts,protocol,i,-1]
            number_information[i]=information
        elif ip.p==6:
            protocol='tcp'
            tcp= ip.data
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
    ################################ 获得sni 屎山代码勿动 ###################################
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
    ################################ 获得sni 屎山代码勿动 ###################################
                else:
                    try:
                        ## 两个tcp合并怎么办，保存第一个，第二个开始计算
                        # 经测试，前面有杂数据没有关系。
                        request = dpkt.http.Request(tcp.data)
                        stream_http_data[stream]=[tcp.data,[i]]
                        
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
                    
                
            
            if stream not in stream_nums:
                stream_nums[stream]=[i]
            else:
                stream_nums[stream].append(i)

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
            
            information=[sip,sport,dip,dport,ts,protocol,i,stream]
            number_information[i]=information
            # out_json.write(json.dumps((os.path.basename(filename),ts,sip,sport,dip,dport,protocol))+"\n")
            

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
        if stream_ip_number[stream][0] in ip_domains_number:
            can_break=False
            for domain,numbers_dns in ip_domains_number[stream_ip_number[stream][0]].items():
                for number_dns in numbers_dns:
                    if 200 > stream_ip_number[stream][1]-number_dns > 0:  # 200个包以内就视为这个流的DNS查询
                        stream_domain[stream]=domain
                        can_break=True
                    if can_break:
                        break
                if can_break:
                    break


    
    # if not os.path.exists(out_packet_dir+'/'):
    #     os.makedirs(out_packet_dir)
    # out_json=open(out_packet_dir+'/'+os.path.basename(filename)+'.json','w')
    # for number,information in number_information.items():
    #     if information[7]<0:
    #         tunnel=0
    #     else:
    #         if stream_domain[information[7]] in src_domains:
    #             tunnel=1
    #         else:
    #             tunnel=0
    #     out_json.write(json.dumps((tunnel,information[0],information[1],information[2],information[3],information[4],information[5],information[6],os.path.basename(filename)))+"\n")
    # out_json.close()

    if not os.path.exists(out_flow_dir+'/'):
        os.makedirs(out_flow_dir)
    out_json=open(out_flow_dir+'/'+os.path.basename(filename)+'.json','w')
    for stream,domain in stream_domain.items():
        if domain  not in src_domains:
            tunnel=0
        else:
            tunnel=1   ## proxy_packetstream_io --> tunnel --> 1
        information=number_information[stream_nums[stream][0]]
        out_json.write(json.dumps((tunnel,information[0],information[1],information[2],information[3],information[4],information[5],information[6],os.path.basename(filename)))+"\n")  
    out_json.close()
    # tunnel session/connection session, src_ip, src_port, dst_ip, dst_port, start_time, protocol, pcapfilename

# arabeem.co.uk, aquarius-bee.co.uk... 手动确认 --> tunnel session
# other tcp connection with api.honeygain.com, cloudflare-dns.com --> relayed session
def out_label_honeygain_tunnel(filename):
    # filename=sys.argv[1]

    src_ips=['172.19.0.2','172.19.0.3','172.19.0.4']
    src_domains=['aquarius-bee.co.uk','arabeem.co.uk','aquilabee.nl']
    non_need_domains=['api.honeygain.com','cloudflare-dns.com']

    number_information={}

    # 处理DNS所需要的变量
    ip_domains_number={}
    ip_domains={}
    domain_ips={}
    stream_domain={}
    stream_ip_number={}

    stream_http_data={}

    #当前stream号码
    stream_num=0
    #定义以172.19.0.2放在开头 '172.19.0.2_36450_172.67.74.242_443'--->[]
    ips_ports__stream_startN_startT_endN_endT={}
    # 定义一个流的方法: src ip port,dst ip port, timestamp:后面的包跟第一个相差时间不超过半小时则视为同一条流。1800s
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
            information=[sip,sport,dip,dport,ts,protocol,i,-1]
            number_information[i]=information
        elif ip.p==6:
            protocol='tcp'
            tcp= ip.data
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
    ################################ 获得sni 屎山代码勿动 ###################################
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
    ################################ 获得sni 屎山代码勿动 ###################################
                else:
                    try:
                        ## 两个tcp合并怎么办，保存第一个，第二个开始计算
                        # 经测试，前面有杂数据没有关系。
                        request = dpkt.http.Request(tcp.data)
                        stream_http_data[stream]=[tcp.data,[i]]
                        
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
                    
                
            
            if stream not in stream_nums:
                stream_nums[stream]=[i]
            else:
                stream_nums[stream].append(i)

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
            
            information=[sip,sport,dip,dport,ts,protocol,i,stream]
            number_information[i]=information
            # out_json.write(json.dumps((os.path.basename(filename),ts,sip,sport,dip,dport,protocol))+"\n")
            

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
        if stream_ip_number[stream][0] in ip_domains_number:
            can_break=False
            for domain,numbers_dns in ip_domains_number[stream_ip_number[stream][0]].items():
                for number_dns in numbers_dns:
                    if 200 > stream_ip_number[stream][1]-number_dns > 0:  # 200个包以内就视为这个流的DNS查询
                        stream_domain[stream]=domain
                        can_break=True
                    if can_break:
                        break
                if can_break:
                    break


    if not os.path.exists(out_flow_dir+'/'):
        os.makedirs(out_flow_dir)
    out_json=open(out_flow_dir+'/'+os.path.basename(filename)+'.json','w')
    for stream,domain in stream_domain.items():
        if domain  in src_domains:
            tunnel=1
        else:
            tunnel=0
        information=number_information[stream_nums[stream][0]]
        out_json.write(json.dumps((tunnel,information[0],information[1],information[2],information[3],information[4],information[5],information[6],os.path.basename(filename)))+"\n")

    out_json.close()
    # tunnel session/connection session, src_ip, src_port, dst_ip, dst_port, start_time, protocol, pcapfilename



# unresolved ip --> Tunnel Session ->1
# other tcp without api.iproyal.com --> Relayed Session
def out_label_iproyal_tunnel(filename):
    # filename=sys.argv[1]

    src_ips=['172.19.0.2','172.19.0.3','172.19.0.4']
    src_domains=['api.iproyal.com']


    number_information={}

    # 处理DNS所需要的变量
    ip_domains_number={}
    ip_domains={}
    domain_ips={}
    stream_domain={}
    stream_ip_number={}
    resolved_ips=[]

    stream_http_data={}

    #当前stream号码
    stream_num=0
    #定义以172.19.0.2放在开头 '172.19.0.2_36450_172.67.74.242_443'--->[]
    ips_ports__stream_startN_startT_endN_endT={}
    # 定义一个流的方法: src ip port,dst ip port, timestamp:后面的包跟第一个相差时间不超过半小时则视为同一条流。1800s
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
                        if an_ip not in resolved_ips:
                            resolved_ips.append(an_ip)
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
            information=[sip,sport,dip,dport,ts,protocol,i,-1]
            number_information[i]=information
        elif ip.p==6:
            protocol='tcp'
            tcp= ip.data
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
    ################################ 获得sni 屎山代码勿动 ###################################
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
    ################################ 获得sni 屎山代码勿动 ###################################
                else:
                    try:
                        ## 两个tcp合并怎么办，保存第一个，第二个开始计算
                        # 经测试，前面有杂数据没有关系。
                        request = dpkt.http.Request(tcp.data)
                        stream_http_data[stream]=[tcp.data,[i]]
                        
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
                    
                
            
            if stream not in stream_nums:
                stream_nums[stream]=[i]
            else:
                stream_nums[stream].append(i)

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
            
            information=[sip,sport,dip,dport,ts,protocol,i,stream]
            number_information[i]=information
            # out_json.write(json.dumps((os.path.basename(filename),ts,sip,sport,dip,dport,protocol))+"\n")
            

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
        if stream_ip_number[stream][0] in ip_domains_number:
            can_break=False
            for domain,numbers_dns in ip_domains_number[stream_ip_number[stream][0]].items():
                for number_dns in numbers_dns:
                    if 200 > stream_ip_number[stream][1]-number_dns > 0:  # 200个包以内就视为这个流的DNS查询
                        stream_domain[stream]=domain
                        can_break=True
                    if can_break:
                        break
                if can_break:
                    break


    
    # if not os.path.exists(out_packet_dir+'/'):
    #     os.makedirs(out_packet_dir)
    # out_json=open(out_packet_dir+'/'+os.path.basename(filename)+'.json','w')
    # for number,information in number_information.items():
    #     if information[7]<0:
    #         tunnel=0
    #     else:
    #         if stream_domain[information[7]] in src_domains:
    #             tunnel=1
    #         else:
    #             tunnel=0
    #     out_json.write(json.dumps((tunnel,information[0],information[1],information[2],information[3],information[4],information[5],information[6],os.path.basename(filename)))+"\n")
    # out_json.close()

    if not os.path.exists(out_flow_dir+'/'):
        os.makedirs(out_flow_dir)
    out_json=open(out_flow_dir+'/'+os.path.basename(filename)+'.json','w')
    for stream,domain in stream_domain.items():
        information=number_information[stream_nums[stream][0]]
        if information[0] not in src_ips:
            if information[0] not in resolved_ips:  # 是unresolved ip
                tunnel=1
            else:
                if domain not in src_domains:
                    tunnel=0
                else:
                    # continue
                    tunnel=0
        else:
            if information[2] not in resolved_ips:
                tunnel=1
            else:
                if domain not in src_domains:
                    tunnel=0
                else:
                    # continue
                    tunnel=0
        out_json.write(json.dumps((tunnel,information[0],information[1],information[2],information[3],information[4],information[5],information[6],os.path.basename(filename)))+"\n")
        # else:
            # out_json.write(json.dumps((tunnel,information[2],information[3],information[0],information[1],information[4],information[5],information[6],os.path.basename(filename)))+"\n")
       
    out_json.close()
    # tunnel session/connection session, src_ip, src_port, dst_ip, dst_port, start_time, protocol, pcapfilename


def main():
    if len(sys.argv)==2:
        print('正在处理文件:',sys.argv[1])
        out_label_packetstream_tunnel(sys.argv[1])
        print('处理文件完成:',sys.argv[1])
    elif len(sys.argv)==3:
        if sys.argv[1].find(sys.argv[2])!=-1:
            print('正在处理文件:',sys.argv[1])
            out_label_packetstream_tunnel(sys.argv[1])
            print('处理文件完成:',sys.argv[1])
        else:
            print('文件:',sys.argv[1]," 未包含字符串:",sys.argv[2])

if __name__ == "__main__":
    main()


# iproyal_aspServer_2022-07-
# iproyal_aspServer_2022-08-
# honeygain_aspServer_2022-
# packetstream_aspServer_2022-07-1