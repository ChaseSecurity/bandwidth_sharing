import json
import pyshark
import sys
import os.path



class Information():
    def __init__(self,src_ip,dst_ip,src_port,dst_port,length,stream,protocal,timestamp,host):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.length = length
        self.stream = stream
        self.protocal = protocal
        self.timestamp = timestamp
        self.host = host


def read_pcap(filename):
    pks=pyshark.FileCapture(filename,keep_packets=False)

    all_base_tcp_len=0
    all_len=0

    src_ips=['172.19.0.2','172.19.0.3','172.19.0.4']
    src_domains=['proxy.packetstream.io','api.packetstream.io']
    stream_ip_number={}  #stream with ip and start number
    stream_timestamp={}
    domain_streams={}
    stream_len={}
    ip_domains={}
    domain_ips={}
    ip_domains_number={}  #记录dns ip对应的域名，以及对应的序号
    files_path=[]

    number_informations={}
    stream_numbers={}

    #read old data
    try:
        input_json=open('read.json','r')
        input_stat=json.load(input_json)
        files_path=input_stat['files_path']
    except:
        print("没有read.json文件")

    if os.path.basename(filename) in files_path:
        print("该文件已经被处理过，跳过处理！")
        return 
    files_path.append(os.path.basename(filename))
    files_path.sort()


    output_stat={}
    output_stat['files_path']=files_path
    output_json=open('read.json','w')
    json.dump(output_stat, output_json)
    output_json.close()
    print("ok")
    return

    base_time=0
    for pkg in pks:
        if pkg.number=='1':
            base_time=float(pkg.sniff_timestamp)
        if int(pkg.number)%1000 == 0:
            print("正在处理第",pkg.number,"个数据包")
        all_len+=int(pkg.length)
        if pkg.highest_layer=='ETH':
            pass
        elif pkg.highest_layer=='IP':
            pass
        elif pkg.highest_layer=='DNS':
            if pkg.dns.has_field('a'):
                #dns respond
                for answer in pkg.dns.a.all_fields:
                    #print(answer.showname_value)
                    if answer.showname_value not in ip_domains_number:
                        ip_domains_number[answer.showname_value]={pkg.dns.qry_name:[int(pkg.number)]}  #int(pkg.number) start with 1！
                    else:
                        if pkg.dns.qry_name not in ip_domains_number[answer.showname_value]:
                            ip_domains_number[answer.showname_value][pkg.dns.qry_name]=[int(pkg.number)]
                        else:
                            ip_domains_number[answer.showname_value][pkg.dns.qry_name].append(int(pkg.number))
                    if answer.showname_value not in ip_domains:
                        ip_domains[answer.showname_value] =set([pkg.dns.qry_name])
                    else:
                        ip_domains[answer.showname_value].add(pkg.dns.qry_name)
                    if pkg.dns.qry_name not in domain_ips:
                        domain_ips[pkg.dns.qry_name]=set([answer.showname_value])
                    else:
                        domain_ips[pkg.dns.qry_name].add(answer.showname_value)
        elif pkg.transport_layer=='TCP':
            # record tcp information
            #                     0            1          2               3            4           5           6               7     8

            information=[pkg.ip.src, pkg.ip.dst,pkg.tcp.srcport,pkg.tcp.dstport,int(pkg.length),pkg.tcp.stream,'',pkg.sniff_timestamp,'']
            
            if pkg.tcp.stream not in stream_numbers:
                stream_numbers[pkg.tcp.stream]=[pkg.number]
            else:
                stream_numbers[pkg.tcp.stream].append(pkg.number)

            # get first tcp stream timestamp
            if pkg.tcp.stream not in stream_timestamp:
                stream_timestamp[pkg.tcp.stream]=float(pkg.sniff_timestamp)-base_time

            if len(pkg.get_multiple_layers('http')) != 0:
                information[6]='http'
                all_base_tcp_len+=int(pkg.length)

                if pkg.tcp.stream not in stream_ip_number:
                    if pkg.ip.src not in src_ips:
                        stream_ip_number[pkg.tcp.stream]=[pkg.ip.src,int(pkg.number)]
                    else:
                        stream_ip_number[pkg.tcp.stream]=[pkg.ip.dst,int(pkg.number)]
                        
                if pkg.tcp.stream not in stream_len:
                    stream_len[pkg.tcp.stream]=int(pkg.length)
                else:
                    stream_len[pkg.tcp.stream]+=int(pkg.length)
                
                pkg_http=pkg.http
                
                if pkg_http.has_field('host'):
                    information[8] = pkg_http.host
                    if pkg_http.host not in domain_streams:
                        domain_streams[pkg_http.host]=set([pkg.tcp.stream])
                    else:
                        domain_streams[pkg_http.host].add(pkg.tcp.stream)
            elif pkg.highest_layer=='TLS':
                information[6]='tls'
                all_base_tcp_len+=int(pkg.length)

                if pkg.tcp.stream not in stream_ip_number:
                    if pkg.ip.src not in src_ips:
                        stream_ip_number[pkg.tcp.stream]=[pkg.ip.src,int(pkg.number)]
                    else:
                        stream_ip_number[pkg.tcp.stream]=[pkg.ip.dst,int(pkg.number)]
                        
                if pkg.tcp.stream not in stream_len:
                    stream_len[pkg.tcp.stream]=int(pkg.length)
                else:
                    stream_len[pkg.tcp.stream]+=int(pkg.length)

                pkg_tls=pkg.tls
                if pkg_tls.has_field('record_content_type') and pkg_tls.has_field('handshake_type'):
                    if pkg_tls.record_content_type=='22' and pkg_tls.handshake_type=='1':
                        #client hello

                        # client_hello_no+=1
                        if pkg_tls.has_field('handshake_extensions_server_name'):
                            information[8]=pkg_tls.handshake_extensions_server_name
                            if pkg_tls.handshake_extensions_server_name not in domain_streams:
                                domain_streams[pkg_tls.handshake_extensions_server_name]=set([pkg.tcp.stream])
                            else:
                                domain_streams[pkg_tls.handshake_extensions_server_name].add(pkg.tcp.stream)
                        else:
                            print("client hello but don't have sni! no.:",pkg.number)
            else:
                information[6]='tcp'
                all_base_tcp_len+=int(pkg.length)

                if pkg.tcp.stream not in stream_ip_number:
                    if pkg.ip.src not in src_ips:
                        stream_ip_number[pkg.tcp.stream]=[pkg.ip.src,int(pkg.number)]
                    else:
                        stream_ip_number[pkg.tcp.stream]=[pkg.ip.dst,int(pkg.number)]

                if pkg.tcp.stream not in stream_len:
                    stream_len[pkg.tcp.stream]=int(pkg.length)
                else:
                    stream_len[pkg.tcp.stream]+=int(pkg.length)

            number_informations[pkg.number]=information
    print("读取完毕，开始处理")
    pks.close()

    #turn set to list
    for domain,streams in domain_streams.copy().items():
        domain_streams[domain]=list(streams)

    for ip,domains in ip_domains.copy().items():
        ip_domains[ip]=list(domains)
    for domain,ips in domain_ips.copy().items():
        domain_ips[domain]=list(ips)


    for stream,length in stream_len.items():
        if stream_ip_number[stream][0] in ip_domains_number:
            can_break=False
            for domain,numbers_dns in ip_domains_number[stream_ip_number[stream][0]].items():
                for number_dns in numbers_dns:
                    if 50 > stream_ip_number[stream][1]-number_dns > 0:  # 50个包以内就视为这个流的DNS查询
                        # add domains ips information
                        if domain not in domain_ips:
                            domain_ips[domain]=[stream_ip_number[stream][0]]
                        else:
                            if stream_ip_number[stream][0] not in domain_ips[domain]:
                                domain_ips[domain].append(stream_ip_number[stream][0])
                        if stream_ip_number[stream][0] not in ip_domains:
                            ip_domains[stream_ip_number[stream][0]]=[domain]
                        else:
                            if domain not in ip_domains[stream_ip_number[stream][0]]:
                                ip_domains[stream_ip_number[stream][0]].append(domain)
                        can_break=True
                    if can_break:
                        break
                if can_break:
                    break




    output_stat={}
    output_stat['files_path']=files_path
    
    output_json=open('read.json','w')
    json.dump(output_stat, output_json)
    output_json.close()

    # write informations for file
    information_json={}
    information_json['filename']=os.path.basename(filename)
    information_json['number_informations']=number_informations
    information_json['base_time']=base_time
    information_json['domain_ips']=domain_ips
    information_json['ip_domains']=ip_domains
    information_json['stream_ip_number']=stream_ip_number
    information_json['stream_timestamp']=stream_timestamp
    information_json['domain_streams']=domain_streams 
    information_json['stream_len']=stream_len
    information_json['ip_domains_number']=ip_domains_number
    information_json['stream_numbers']=stream_numbers
    information_json['all_len']=all_len
    information_json['all_base_tcp_len']=all_base_tcp_len

    information_file = open(os.path.basename(filename)+'_v2.json','w')
    json.dump(information_json,information_file)
    information_file.close()



def main():
    print("正在处理文件：",sys.argv[1])
    read_pcap(sys.argv[1])
    print("处理文件完成：",sys.argv[1])


if __name__ == "__main__":
    main()
