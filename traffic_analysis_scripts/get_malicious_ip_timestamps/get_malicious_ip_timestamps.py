import dpkt
import sys
import socket
import json
import struct
import os

# Placeholder for sensitive IP addresses
malicious_ips = set()

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

def get_malicious_ip_timestamps(filename):
    src_ips=['172.19.0.2','172.19.0.3','172.19.0.4']
    
    server_ips = {
        'anonymous server':'anonymous ip',
    }

    server_ip = ''
    for server,ip in server_ips.items():
        if filename.find(server) != -1:
            server_ip = ip
    if server_ip == '':
        print('error:', filename)
        return
    
    stream_num=0


    #定义以172.19.0.2放在开头 '172.19.0.2_36450_172.67.74.242_443'--->[]
    tcp_ips_ports__stream_startN_startT_endN_endT={}

    udp_stream_len={}

    
    all_len=0
    all_tcp_len=0
    all_udp_len=0

    udp_stream_ip_port={}
    udp_stream_len={}

    files_path=[]
    remote_ip_server_ip_timestamps = {}
    #read old data
    try:
        input_json=open('stat.json','r')
        input_stat=json.load(input_json)
        remote_ip_server_ip_timestamps=input_stat['remote_ip_server_ip_timestamps']
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

    streams = set()
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
            
            
            

            if stream not in streams:
                streams.add(stream)
                if sip not in src_ips:
                    if sip in malicious_ips:
                        if sip not in remote_ip_server_ip_timestamps:
                            remote_ip_server_ip_timestamps[sip]=[]
                            remote_ip_server_ip_timestamps[sip].append([server_ip,ts])
                        else:
                            remote_ip_server_ip_timestamps[sip].append([server_ip,ts])
                else:
                    if dip in malicious_ips:
                        if dip not in remote_ip_server_ip_timestamps:
                            remote_ip_server_ip_timestamps[dip]=[]
                            remote_ip_server_ip_timestamps[dip].append([server_ip,ts])
                        else:
                            remote_ip_server_ip_timestamps[dip].append([server_ip,ts])
                

    

    output_stat={}
    output_stat['remote_ip_server_ip_timestamps']=remote_ip_server_ip_timestamps
    output_stat['files_path']=files_path

    output_json=open('stat.json','w')
    json.dump(output_stat, output_json)
    output_json.close()


                
def main(): 
    if len(sys.argv)==2:
        print('正在处理文件:',sys.argv[1])
        get_malicious_ip_timestamps(sys.argv[1])
        print('处理文件完成:',sys.argv[1])
    elif len(sys.argv)==3:
        if sys.argv[1].find(sys.argv[2])!=-1:
            print('正在处理文件:',sys.argv[1])
            get_malicious_ip_timestamps(sys.argv[1])
            print('处理文件完成:',sys.argv[1])
        else:
            print('文件:',sys.argv[1]," 未包含字符串:",sys.argv[2])


if __name__ == "__main__":
    main()
 