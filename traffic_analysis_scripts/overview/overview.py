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


    #当前stream号码
    tcp_stream_num=0
    #定义以172.19.0.2放在开头 '172.19.0.2_36450_172.67.74.242_443'--->[]
    tcp_ips_ports__stream_startN_startT_endN_endT={}

    udp_stream_len={}

    
    all_len=0
    all_tcp_len=0
    all_udp_len=0

    tcp_port_len_number={}
    udp_port_filename_ip_len_number={}

    tcp_stream_ip_port={}
    udp_stream_ip_port={}

    tcp_stream_len={}
    udp_stream_len={}

    files_path=[]
    #read old data
    try:
        input_json=open('stat.json','r')
        input_stat=json.load(input_json)
        udp_port_filename_ip_len_number=input_stat['udp_port_filename_ip_len_number']
        tcp_port_len_number=input_stat['tcp_port_len_number']
        all_len=input_stat['all_len']
        all_tcp_len=input_stat['all_tcp_len']
        all_udp_len=input_stat['all_udp_len']
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
                    tcp_ips_ports__stream_startN_startT_endN_endT[index].append([tcp_stream_num,i,ts,i,ts])
                    stream=tcp_stream_num
                    tcp_stream_num+=1
                    
                else:
                    if ts-tcp_ips_ports__stream_startN_startT_endN_endT[index][len(tcp_ips_ports__stream_startN_startT_endN_endT[index])-1][4]<1800:
                        stream=tcp_ips_ports__stream_startN_startT_endN_endT[index][len(tcp_ips_ports__stream_startN_startT_endN_endT[index])-1][0]
                        tcp_ips_ports__stream_startN_startT_endN_endT[index][len(tcp_ips_ports__stream_startN_startT_endN_endT[index])-1][4]=ts
                        tcp_ips_ports__stream_startN_startT_endN_endT[index][len(tcp_ips_ports__stream_startN_startT_endN_endT[index])-1][3]=i
                    else:
                        stream=tcp_stream_num
                        tcp_ips_ports__stream_startN_startT_endN_endT[index].append([tcp_stream_num,i,ts,i,ts])
                        tcp_stream_num+=1
            else:
                index=sip+"_"+str(sport)+"_"+dip+str(dport)
                if index not in tcp_ips_ports__stream_startN_startT_endN_endT:
                    tcp_ips_ports__stream_startN_startT_endN_endT[index]=[]
                    tcp_ips_ports__stream_startN_startT_endN_endT[index].append([tcp_stream_num,i,ts,i,ts])
                    stream=tcp_stream_num
                    tcp_stream_num+=1
                    
                else:
                    if ts-tcp_ips_ports__stream_startN_startT_endN_endT[index][len(tcp_ips_ports__stream_startN_startT_endN_endT[index])-1][4]<1800:
                        stream=tcp_ips_ports__stream_startN_startT_endN_endT[index][len(tcp_ips_ports__stream_startN_startT_endN_endT[index])-1][0]
                        tcp_ips_ports__stream_startN_startT_endN_endT[index][len(tcp_ips_ports__stream_startN_startT_endN_endT[index])-1][4]=ts
                        tcp_ips_ports__stream_startN_startT_endN_endT[index][len(tcp_ips_ports__stream_startN_startT_endN_endT[index])-1][3]=i
                    else:
                        stream=tcp_stream_num
                        tcp_ips_ports__stream_startN_startT_endN_endT[index].append([tcp_stream_num,i,ts,i,ts])
                        tcp_stream_num+=1
            
            if stream not in tcp_stream_ip_port:
                if sip not in src_ips:
                    tcp_stream_ip_port[stream]=[sip,sport]
                else:
                    tcp_stream_ip_port[stream]=[dip,dport]
                
            if stream not in tcp_stream_len:
                tcp_stream_len[stream]=buf_len
            else:
                tcp_stream_len[stream]+=buf_len
    
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
        if  port not in tcp_port_len_number:
            tcp_port_len_number[port]=[tcp_stream_len[stream],1]
        else:
            tcp_port_len_number[port][0]+=tcp_stream_len[stream]
            tcp_port_len_number[port][1]+=1

   

    output_stat={}
    output_stat['udp_port_filename_ip_len_number']=udp_port_filename_ip_len_number
    output_stat['tcp_port_len_number']=tcp_port_len_number
    output_stat['all_len']=all_len
    output_stat['all_tcp_len']=all_tcp_len
    output_stat['all_udp_len']=all_udp_len
    output_stat['files_path']=files_path

    output_json=open('stat.json','w')
    json.dump(output_stat, output_json)
    output_json.close()

def space():
    #read old data
    try:
        input_json=open('stat.json','r')
        input_stat=json.load(input_json)
        udp_port_filename_ip_len_number=input_stat['udp_port_filename_ip_len_number']
        tcp_port_len_number=input_stat['tcp_port_len_number']
        all_len=input_stat['all_len']
        all_tcp_len=input_stat['all_tcp_len']
        all_udp_len=input_stat['all_udp_len']
        files_path=input_stat['files_path']
        input_json.close()
    except:
        print("没有json文件")
        return
    # write data
    output_txt=open('stat.txt', 'w')
    output_txt.write("所有来源文件:\n")
    for file_name in files_path:
        output_txt.write(file_name+"\n")
    output_txt.close()

    udp_flow_num=0
    udp_flow_len=0

    tcp_flow_num=0
    tcp_flow_len=0

    udp_port_len_number={}
    for port,filename_ip_len_number in udp_port_filename_ip_len_number.items():
        udp_port_len_number[port]=[0,0]
        for filename, ip_len_number in filename_ip_len_number.items():
            for ip,len_number in ip_len_number.items():
                udp_flow_len+=len_number[0]
                udp_flow_num+=len_number[1]
                udp_port_len_number[port][0]+=len_number[0]
                udp_port_len_number[port][1]+=len_number[1]

    for  port,len_number in  tcp_port_len_number.items():
        tcp_flow_len+=len_number[0]
        tcp_flow_num+=len_number[1]

    output_txt=open('stat2.txt', 'w')
    output_txt.write('all_len:'+str(all_len)+'\n')
    output_txt.write('all_tcp_len:'+str(all_tcp_len)+'\n')
    output_txt.write('all_udp_len:'+str(all_udp_len)+'\n')
    output_txt.write('all_len:'+str(all_tcp_len+all_udp_len)+'\n')
    output_txt.write('udp flow num:'+str(udp_flow_num)+'\n')
    output_txt.write('udp_flow_len:'+str(udp_flow_len)+'\n')
    output_txt.write('tcp flow num:'+str(tcp_flow_num)+'\n')
    output_txt.write('tcp_flow_len:'+str(tcp_flow_len)+'\n')
    output_txt.close()

    

    list_1 = list(udp_port_len_number.items())
    print('udp:')
    print('udp 总流量:',udp_flow_len)
    print('udp 总flow:',udp_flow_num)
    udp_port_len_number_sort= dict(sorted(list_1,key = lambda x:x[1][0],reverse= True))
    for port,len_number in udp_port_len_number_sort.items():
        print(port,len_number,round(len_number[0]*100/udp_flow_len,2),round(len_number[1]*100/udp_flow_num,2))
    
    print('udp:')
    print('udp 总流量:',udp_flow_len)
    print('udp 总flow:',udp_flow_num)
    udp_port_len_number_sort= dict(sorted(list_1,key = lambda x:x[1][0],reverse= True))
    for port,len_number in udp_port_len_number_sort.items():
        print(port,len_number,round(len_number[0]*100/udp_flow_len,2),round(len_number[1]*100/udp_flow_num,2))
    
    print('tcp:')
    print('tcp 总流量:',tcp_flow_len)
    print('tcp 总flow:',tcp_flow_num)
    http_s_flow_num=0
    http_s_flow_len=0

    smtp_len=0
    imap_len=0
    pop3_len=0
    other_len=0
    unknown_len=0

    smtp_num=0
    imap_num=0
    pop3_num=0
    other_num=0
    unknown_num=0


    list_1 = list(tcp_port_len_number.items())
    tcp_port_len_number_sort= dict(sorted(list_1,key = lambda x:x[1][0],reverse= True))
    for port,len_number in tcp_port_len_number_sort.items():
        if port in ['80','443']:
            http_s_flow_num+=len_number[1]
            http_s_flow_len+=len_number[0]
        if port in ['25','587']:
            smtp_num+=len_number[1]
            smtp_len+=len_number[0]
        if port in ['110','993']:
            imap_num+=len_number[1]
            imap_len+=len_number[0]
        if port in ['143','995']:
            pop3_num+=len_number[1]
            pop3_len+=len_number[0]
        if int(port)<=1023:
            other_num+=len_number[1]
            other_len+=len_number[0]
        else:
            unknown_num+=len_number[1]
            unknown_len+=len_number[0]
        
        print(port,len_number,round(len_number[0]*100/tcp_flow_len,2),round(len_number[1]*100/tcp_flow_num,2))
    
    for port,len_number in udp_port_len_number_sort.items():
        if int(port)<=1023:
            other_num+=len_number[1]
            other_len+=len_number[0]
        else:
            unknown_num+=len_number[1]
            unknown_len+=len_number[0]
    print(udp_port_len_number_sort)
    print('tcp_flow_num/all:',round(tcp_flow_num*100/(tcp_flow_num+udp_flow_num),2))
    print('tcp_flow_len/all:',round(tcp_flow_len*100/(tcp_flow_len+udp_flow_len),2))
    print('http_s:',round(http_s_flow_len*100/tcp_flow_len,2),round(http_s_flow_num*100/tcp_flow_num,2))
    print('smtp:',round(smtp_len*100/tcp_flow_len,2),round(smtp_num*100/tcp_flow_num,2))
    print('imap:',round(imap_num*100/tcp_flow_len,2),round(imap_num*100/tcp_flow_num,2))
    print('pop3:',round(pop3_len*100/tcp_flow_len,2),round(pop3_num*100/tcp_flow_num,2))
    print('other:',round((other_len-pop3_len-smtp_len-imap_len-http_s_flow_len)*100/tcp_flow_len,2),round((other_num-smtp_num-imap_num-pop3_num-http_s_flow_num)*100/tcp_flow_num,2))
    print('unknown:',round((unknown_len-tcp_port_len_number_sort['30944'][0])*100/tcp_flow_len,2),round((unknown_num-tcp_port_len_number_sort['30944'][1])*100/tcp_flow_num,2))
    
    print('tcp_flow_num/all:',round(tcp_flow_num*100/(tcp_flow_num+udp_flow_num),2))
    print('tcp_flow_len/all:',round(tcp_flow_len*100/(tcp_flow_len+udp_flow_len),2))
    print('packetstream:',round(tcp_port_len_number_sort['30944'][0]*100/(tcp_flow_len+udp_flow_len),2),round(tcp_port_len_number_sort['30944'][1]*100/(tcp_flow_num+udp_flow_num),2))
    print('http_s:',round(http_s_flow_len*100/(tcp_flow_len+udp_flow_len),2),round(http_s_flow_num*100/(tcp_flow_num+udp_flow_num),2))
    print('smtp:',round(smtp_len*100/(tcp_flow_len+udp_flow_len),2),round(smtp_num*100/(tcp_flow_num+udp_flow_num),2))
    print('imap:',round(imap_num*100/(tcp_flow_len+udp_flow_len),2),round(imap_num*100/(tcp_flow_num+udp_flow_num),2))
    print('pop3:',round(pop3_len*100/(tcp_flow_len+udp_flow_len),2),round(pop3_num*100/(tcp_flow_num+udp_flow_num),2))
    print('other:',round((other_len-pop3_len-smtp_len-imap_len-http_s_flow_len-udp_port_len_number_sort['53'][0])*100/(tcp_flow_len+udp_flow_len),2),round((other_num-smtp_num-imap_num-pop3_num-http_s_flow_num-udp_port_len_number_sort['53'][1])*100/(tcp_flow_num+udp_flow_num),2))
    print('unknown:',round((unknown_len-tcp_port_len_number_sort['30944'][0])*100/(tcp_flow_len+udp_flow_len),2),round((unknown_num-tcp_port_len_number_sort['30944'][1])*100/(tcp_flow_num+udp_flow_num),2))
    print('dns:',round(udp_port_len_number_sort['53'][0]*100/(tcp_flow_len+udp_flow_len),2),round(udp_port_len_number_sort['53'][1]*100/(tcp_flow_num+udp_flow_num),2))
    print('http:',round(tcp_port_len_number_sort['80'][0]*100/(tcp_flow_len+udp_flow_len),2),round(tcp_port_len_number_sort['80'][1]*100/(tcp_flow_num+udp_flow_num),2))
    print('https:',round(tcp_port_len_number_sort['443'][0]*100/(tcp_flow_len+udp_flow_len),2),round(tcp_port_len_number_sort['443'][1]*100/(tcp_flow_num+udp_flow_num),2))



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
 
