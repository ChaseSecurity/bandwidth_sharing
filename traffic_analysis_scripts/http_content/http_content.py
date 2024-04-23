import json
import dpkt
import sys
import os.path
import struct
import socket

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

def http_content(file_name):
    filename=os.path.basename(file_name)

    src_ips=['172.19.0.2','172.19.0.3','172.19.0.4']
    http_request={}
    files_path=[]
    #read old data
    try:
        input_json=open('stat.json','r')
        input_stat=json.load(input_json)
        http_request=input_stat['http_request']
        files_path=input_stat['files_path']
        input_json.close()
    except:
        print("没有json文件")

    if os.path.basename(filename) in files_path:
        print("该文件已经被处理过，跳过处理！")
        return 
    files_path.append(os.path.basename(filename))
    files_path.sort()


# 处理DNS所需要的变量
    ip_domains_number={}
    ip_domains={}
    domain_ips={}
    stream_url={}
    stream_domain={}
    stream_ip_number_port={}

    stream_len={}

    stream_http_data={}

    stream_http_request={}

    stream_http=[]

    #当前stream号码
    stream_num=0
    #定义以172.19.0.2放在开头 '172.19.0.2_36450_172.67.74.242_443'--->[]
    ips_ports__stream_startN_startT_endN_endT={}
    # 定义一个流的方法: src ip port,dst ip port, timestamp:后面的包跟第一个相差时间不超过半小时则视为同一条流。1800s
    stream_nums={}

    f=open(file_name,'rb')
    
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
            
            if len(s_stream) != 0:
                # continue
                if (s_stream[0]) in {20, 21, 22, 23}:
                    continue
                else:
                    try:
                        ## 两个tcp合并怎么办，保存第一个，第二个开始计算
                        request = dpkt.http.Request(tcp.data)
                        stream_http_data[stream]=[tcp.data,[i]]
                        stream_http_request[stream]=[tcp.data,[i]]
                        is_http=True
                    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                        if stream in stream_http_data and sip in src_ips:  #保证是本地发过去的第二个包
                            try:
                                request = dpkt.http.Request(stream_http_data[stream][0]+tcp.data)
                                url=request.uri
                                if url[0:5] != 'http:': #第二次query
                                    url='http://'+stream_domain[stream]+url
                                if stream not in stream_url:
                                    stream_url[stream]=[url]
                                else:
                                    stream_url[stream].append(url)
                                host=request.headers.get('host')
                                if host is None:
                                    host=''
                                del stream_http_data[stream] #删除缓存，同一条流可能有多个request
                            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):  #如果还缺数据，继续缓存
                                stream_http_data[stream][0]+=tcp.data
                                stream_http_data[stream][1].append(i)

                                stream_http_request[stream][0]+=tcp.data
                                stream_http_request[stream][1].append(i)
                    
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
            if url[0:5] != 'http:': 
                url='http://'+stream_domain[stream]+url
            if stream not in stream_url:
                stream_url[stream]=[url]
            else:
                stream_url[stream].append(url)
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


    http_request[file_name]=[]
    for stream,http_data in stream_http_request.items():
        try:
            request = dpkt.http.Request(http_data[0])
            http_request[file_name].append([str(http_data[0]),http_data[1]])
        except:
            continue
    
    output_stat={}
    output_stat['http_request']=http_request
    output_stat['files_path']=files_path
    
    output_json=open('stat.json','w')
    json.dump(output_stat, output_json)
    output_json.close()

def space():
    try:
        input_json=open('stat.json','r')
        input_stat=json.load(input_json)
        http_request=input_stat['http_request']
        files_path=input_stat['files_path']
        input_json.close()
    except:
        print("没有json文件")

    # http 修正
    for domain,number_filename_stream_url_arr in http_request.copy().items():
        for filename,stream_url_length in number_filename_stream_url_arr[1].items():
            for stream,url_length in stream_url_length.items():
                if url_length[0][0:7]!='http://' and url_length[0][0:8]!='https://':
                    if url_length[0][0]!='/':
                        http_request[domain][1][filename][stream][0]='http://'+http_request[domain][1][filename][stream][0]
                    else:
                        http_request[domain][1][filename][stream][0]='http://'+domain +http_request[domain][1][filename][stream][0]
                if url_length[0][0:8]=='http:///':
                    http_request[domain][1][filename][stream][0]='http://'+domain+ http_request[domain][1][filename][stream][0][7:]
                    
    # write data
    output_txt=open('stat.txt', 'w')
    output_txt.write("所有来源文件:\n")
    for file_name in files_path:
        output_txt.write(file_name+"\n")
    output_txt.write("\n")
    output_txt2=open('stat2.txt', 'w')
    domain_number={}
    for domain,number_filename_stream_url_arr in http_request.items():
        domain_number[domain]=number_filename_stream_url_arr[0]

    list_1=list(domain_number.items())
    domain_number_sort=dict(sorted(list_1,key=lambda x:x[1],reverse=True))
    
    for domain,number in domain_number_sort.items():
        output_txt2.write(domain+","+str(number)+"\n")

    output_txt3=open('stat3.txt', 'w')
    output_txt3.write("\n含有关键字域名或url:\n")
    for domain,number_filename_stream_url_arr in http_request.items():
        output_txt3.write(domain+","+str(number_filename_stream_url_arr[0])+"\n")
        for filename,stream_url_length in number_filename_stream_url_arr[1].items():
            output_txt3.write("\t"+filename+"\n")
            for stream,url_length in stream_url_length.items():
                output_txt3.write("\t\t"+stream+","+url_length[0]+",length:"+str(url_length[1])+"\n")
        output_txt3.write("\n")
    output_txt3.close()


def main():
    if len(sys.argv)==2:
            print('正在处理文件:',sys.argv[1])
            http_content(sys.argv[1])
            print('处理文件完成:',sys.argv[1])
    elif len(sys.argv)>=2:
        if sys.argv[1].find(sys.argv[2])!=-1:
            print('正在处理文件:',sys.argv[1])
            http_content(sys.argv[1])
            print('处理文件完成:',sys.argv[1])
        else:
            print('文件:',sys.argv[1]," 未包含字符串:",sys.argv[2])
    elif len(sys.argv)==1:
        space()


if __name__ == "__main__":
    main()