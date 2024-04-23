import dpkt
import sys
import socket
import json
import struct
import os
import re

def get_mail(filename):
    

    src_ips=['172.19.0.2','172.19.0.3','172.19.0.4']

    # 处理smtp所需要的变量
    stream_mail_content={}
    server_information={}
    files_path=[]


    #当前stream号码
    stream_num=0
    #定义以172.19.0.2放在开头 '172.19.0.2_36450_172.67.74.242_443'--->[]
    ips_ports__stream_startN_startT_endN_endT={}
    # 定义一个流的方法: src ip port,dst ip port, timestamp:后面的包跟第一个相差时间不超过半小时则视为同一条流。1800s



    try:
        input_json=open('read.json','r')
        input_stat=json.load(input_json)
        files_path=input_stat['files_path']
        server_information=input_stat['server_information']
    except:
        print("没有read.json文件")

    if os.path.basename(filename) in files_path:
        print("该文件已经被处理过，跳过处理！")
        return 
    files_path.append(os.path.basename(filename))
    files_path.sort()



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
            # udp continue
            continue 
            
        elif ip.p==6:
            protocol='tcp'
            tcp= ip.data
            sport=tcp.sport
            dport=tcp.dport
  
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
            
            if (sip not in src_ips and sport==25) :  #smtp
                # content = str(tcp.data).split("'")[1]
                content=str(tcp.data)[2:-1]
                

                if content=='':
                    continue
                # content_re = re.sub(r"\\r|\\n", "", content)
                if stream not in stream_mail_content:
                    stream_mail_content[stream]=[sip,str(sport),'',[]]
                    stream_mail_content[stream][3].append(content)
                else:
                    stream_mail_content[stream][3].append(content)
            elif (dip not in src_ips and dport==25):
                content=str(tcp.data)[2:-1]

                if content=='':
                    continue
                if stream not in stream_mail_content:
                    stream_mail_content[stream]=[dip,str(dport),'',[]]  # 下标2无内容，算遗留问题
                    stream_mail_content[stream][3].append(content)
                else:
                    stream_mail_content[stream][3].append(content)


    
    for stream, mail_information in stream_mail_content.items():
        # deal with content
        phase=0
        k1=0
        k2=0
        host=''
        mail_from=''
        mail_to_list=[]
        mail_to=''
        mail_content=''
        con_content=''
        for content in mail_information[3]:
            # for key,contents in msg.items():
            #     for content in contents:
            mail_content+=content
            if phase==0:
                if content.find('220')!=-1:
                    if content.find('220 ')!=-1:
                        k0=content.find('220')
                        k1=content.find(' ',k0)
                        k2=content.find(' ',k1+1)
                    elif content.find('220-')!=-1:
                        k0=content.find('220-')
                        k1=content.find('-',k0)
                        k2=content.find('-',k1+1)
                    host=content[k1+1:k2]
                    phase+=1
                
                    if host not in server_information:#server_host -> ips,ports,ip_port,froms,tos,from_to_content,other_host,number
                        server_information[host]=[[],[],[],{},{},[],[],1]
                        server_information[host][0].append(mail_information[0])
                        # server_information[host][1].append(mail_information[1])
                        # server_information[host][2].append(mail_information[0]+":"+mail_information[1])
                    else:
                        server_information[host][7]+=1
                        if mail_information[0] not in server_information[host][0]:
                            server_information[host][0].append(mail_information[0])
                        # if mail_information[1] not in server_information[host][1]:
                        #     server_information[host][1].append(mail_information[1])
                        # if mail_information[0]+":"+mail_information[1] not in server_information[host][2]:
                        #     server_information[host][2].append(mail_information[0]+":"+mail_information[1])
            if phase==1:
                if content.find('MAIL FROM:<')!=-1:
                    # print(content)
                    k0=content.find('MAIL FROM:<')+11
                    k1=content.find('>')
                    mail_from=content[k0:k1]
                    if mail_from not in server_information[host][3]:
                        server_information[host][3][mail_from]=1
                    else:
                        server_information[host][3][mail_from]+=1
                    phase+=1

                find_rcpt_content=content
                while find_rcpt_content.find('RCPT TO:<')!=-1:
                    k0=find_rcpt_content.find('RCPT TO:<')+9
                    k1=find_rcpt_content.find('>',k0)
                    mail_to=find_rcpt_content[k0:k1]
                    if mail_to not in server_information[host][4]:
                        server_information[host][4][mail_to]=1
                    else:
                        server_information[host][4][mail_to]+=1
                    find_rcpt_content=find_rcpt_content[k1+1:]
                    mail_to_list.append(mail_to)
                if content.find('RCPT TO:<')!=-1:
                    phase+=1
            if phase==3:
                if content.find('DATA')!=-1:
                    phase+=1
            if phase==4:
                if content.find('354')!=-1:
                    phase+=1
            if phase==5:
                if content.find('\\r\\n.\\r\\n')==-1:
                    con_content+=content
                else:
                    phase+=1
            if phase==6:
                if content.find('250 ')==-1:
                    pass
                else:
                    # print('250 OK!')
                    phase+=1
                    
    # record content
        if mail_content !='':
            server_information[host][5].append([mail_from,mail_to_list,mail_content,filename,con_content,phase])
    

    for server,information in server_information.copy().items():
        list_1 = list(information[3].items())
        mail_from_sort= dict(sorted(list_1,key = lambda x:x[1],reverse= True))

        list_2 = list(information[4].items())
        mail_to_sort= dict(sorted(list_2,key = lambda x:x[1],reverse= True))

        server_information[server][3]=mail_from_sort
        server_information[server][4]=mail_to_sort

    output_txt=open('mail.txt','w')
    output_txt.write("所有来源文件:\n")
    for file_name in files_path:
        output_txt.write(file_name+"\n")
    for server,information in server_information.items():
        output_txt.write(server+","+str(information[7])+"\n")
        output_txt.write("\t所有的ip:\n")
        for ip in information[0]:
            output_txt.write("\t\t"+ip+"\n")
        output_txt.write("\t所有的端口:\n")
        for port in information[1]:
            output_txt.write("\t\t"+port+"\n")
        # output_txt.write("\t所有的ip+端口:",information[2])
        output_txt.write("\t所有的发送方邮箱:\n")
        for mail_from,num in information[3].items():
            output_txt.write("\t\t"+mail_from+","+str(num)+"\n")
        output_txt.write("\t所有的接收方邮箱:\n")
        for mail_to,num in information[4].items():
            output_txt.write("\t\t"+mail_to+","+str(num)+"\n")
        can_print=True
        for i in range(len(information[5])):
            if information[5][i][5]>=3:
                if can_print:
                    output_txt.write("\t所有邮件:\n")
                    can_print=False
                output_txt.write("\t\t发送方:"+information[5][i][0]+",接收方:"+str(information[5][i][1])+",来源文件:"+str(information[5][i][3])+"\n")
        output_txt.write("\n")
    output_txt.close()

    output2_txt=open('mail2.txt','w')
    for server,information in server_information.items():
        can_print=True
        for i in range(len(information[5])):
            if can_print:
                output2_txt.write(server+"\n")
                output2_txt.write("\t所有邮件:\n")
                can_print=False
            output2_txt.write("发送方:"+information[5][i][0]+",接收方:"+str(information[5][i][1])+",来源文件:"+str(information[5][i][3])+"\n")
            output2_txt.write("\t邮件内容:\n")
            output2_txt.write(information[5][i][2]+"\n")
        output2_txt.write("\n")
    output2_txt.close()

    output_txt3=open('mail3.txt','w')
    for server,information in server_information.items():
        can_print=True
        for i in range(len(information[5])):
            if information[5][i][5]>3:
                if can_print:
                    output_txt3.write(server+"\n")
                    output_txt3.write("\t所有邮件:\n")
                    can_print=False
                output_txt3.write("发送方:"+information[5][i][0]+",接收方:"+str(information[5][i][1])+",来源文件:"+str(information[5][i][3])+"\n")
                output_txt3.write("\t邮件内容:\n")
                output_txt3.write(information[5][i][4]+"\n")
        if not can_print:
            output_txt3.write("\n")
    output_txt3.close()

    clear_server_information={}
    #  ips,ports,ips_ports,froms,tos,from_to_content,other_host,number
    for s,information in server_information.items():
        s1=s[:s.rfind('.')]
        s2=s1[s1.rfind('.')+1:]
        host=s2+s[s.rfind('.'):]
        if host not in clear_server_information:
            clear_server_information[host]=information
        else:
            for ip in information[0]:
                if ip not in clear_server_information[host][0]:
                    clear_server_information[host][0].append(ip)
            for mail_from,num in information[3].items():
                if mail_from not in clear_server_information[host][3]:
                    clear_server_information[host][3][mail_from]=num
                else:
                    clear_server_information[host][3][mail_from]+=num
            for mail_to,num in information[4].items():
                if mail_to not in clear_server_information[host][4]:
                    clear_server_information[host][4][mail_to]=num
                else:
                    clear_server_information[host][4][mail_to]+=num
            for mail_info in information[5]:
                clear_server_information[host][5].append(mail_info)
            clear_server_information[host][7]+=information[7]
    for server,information in clear_server_information.copy().items():
        list_1 = list(information[3].items())
        mail_from_sort= dict(sorted(list_1,key = lambda x:x[1],reverse= True))

        list_2 = list(information[4].items())
        mail_to_sort= dict(sorted(list_2,key = lambda x:x[1],reverse= True))

        clear_server_information[server][3]=mail_from_sort
        clear_server_information[server][4]=mail_to_sort

    output_txt4=open('mail4.txt','w')
    output_txt4.write("所有来源文件:\n")
    for file_name in files_path:
        output_txt4.write(file_name+"\n")
    for server,information in clear_server_information.items():
        output_txt4.write(server+","+str(information[7])+"\n")
        output_txt4.write("\t所有的ip:\n")
        for ip in information[0]:
            output_txt4.write("\t\t"+ip+"\n")
        output_txt4.write("\t所有的端口:\n")
        for port in information[1]:
            output_txt4.write("\t\t"+port+"\n")
        # output_txt4.write("\t所有的ip+端口:",information[2])
        output_txt4.write("\t所有的发送方邮箱:\n")
        for mail_from,num in information[3].items():
            output_txt4.write("\t\t"+mail_from+","+str(num)+"\n")
        output_txt4.write("\t所有的接收方邮箱:\n")
        for mail_to,num in information[4].items():
            output_txt4.write("\t\t"+mail_to+","+str(num)+"\n")
        can_print=True
        for i in range(len(information[5])):
            if information[5][i][5]>=3:
                if can_print:
                    output_txt4.write("\t所有邮件:\n")
                    can_print=False
                output_txt4.write("\t\t发送方:"+information[5][i][0]+",接收方:"+str(information[5][i][1])+",来源文件:"+str(information[5][i][3])+"\n")
            # output_txt4.write("\t邮件内容:\n")
            # output_txt4.write(information[5][i][2]+"\n")
        output_txt4.write("\n")
    output_txt4.close()


    output_stat={}
    output_stat['files_path']=files_path
    output_stat['server_information']=server_information
    
    output_json=open('read.json','w')
    json.dump(output_stat, output_json)
    output_json.close()

def space():

    # 处理smtp所需要的变量
    server_information={}
    files_path=[]





    try:
        input_json=open('read.json','r')
        input_stat=json.load(input_json)
        files_path=input_stat['files_path']
        server_information=input_stat['server_information']
    except:
        print("没有read.json文件")


    for server,information in server_information.copy().items():
        list_1 = list(information[3].items())
        mail_from_sort= dict(sorted(list_1,key = lambda x:x[1],reverse= True))

        list_2 = list(information[4].items())
        mail_to_sort= dict(sorted(list_2,key = lambda x:x[1],reverse= True))

        server_information[server][3]=mail_from_sort
        server_information[server][4]=mail_to_sort

    output_txt=open('mail.txt','w')
    output_txt.write("所有来源文件:\n")
    for file_name in files_path:
        output_txt.write(file_name+"\n")
    for server,information in server_information.items():
        output_txt.write(server+","+str(information[7])+"\n")
        output_txt.write("\t所有的ip:\n")
        for ip in information[0]:
            output_txt.write("\t\t"+ip+"\n")
        output_txt.write("\t所有的端口:\n")
        for port in information[1]:
            output_txt.write("\t\t"+port+"\n")
        # output_txt.write("\t所有的ip+端口:",information[2])
        output_txt.write("\t所有的发送方邮箱:\n")
        for mail_from,num in information[3].items():
            output_txt.write("\t\t"+mail_from+","+str(num)+"\n")
        output_txt.write("\t所有的接收方邮箱:\n")
        for mail_to,num in information[4].items():
            output_txt.write("\t\t"+mail_to+","+str(num)+"\n")
        can_print=True
        for i in range(len(information[5])):
            if information[5][i][5]>=3:
                if can_print:
                    output_txt.write("\t所有邮件:\n")
                    can_print=False
                output_txt.write("\t\t发送方:"+information[5][i][0]+",接收方:"+information[5][i][1]+"\n")
            # output_txt.write("\t邮件内容:\n")
            # output_txt.write(information[5][i][2]+"\n")
        output_txt.write("\n")
    output_txt.close()

    output2_txt=open('mail2.txt','w')
    for server,information in server_information.items():
        can_print=True
        for i in range(len(information[5])):
            if can_print:
                output2_txt.write(server+"\n")
                output2_txt.write("\t所有邮件:\n")
                can_print=False
            output2_txt.write("发送方:"+information[5][i][0]+",接收方:"+information[5][i][1]+"\n")
            output2_txt.write("\t邮件内容:\n")
            output2_txt.write(information[5][i][2]+"\n")
        output2_txt.write("\n")
    output2_txt.close()

    output_txt3=open('mail3.txt','w')
    for server,information in server_information.items():
        can_print=True
        for i in range(len(information[5])):
            if information[5][i][5]>3:
                if can_print:
                    output_txt3.write(server+"\n")
                    output_txt3.write("\t所有邮件:\n")
                    can_print=False
                output_txt3.write("发送方:"+information[5][i][0]+",接收方:"+information[5][i][1]+'来源文件:'+information[5][i][3]+"\n")
                output_txt3.write("\t邮件内容:\n")
                output_txt3.write(information[5][i][4]+"\n")
        output_txt3.write("\n")
    output_txt3.close()

    output_stat={}
    output_stat['files_path']=files_path
    output_stat['server_information']=server_information
    
    output_json=open('read.json','w')
    json.dump(output_stat, output_json)
    output_json.close()    

def main():
    if len(sys.argv)==2:
        
        print("正在处理文件：",sys.argv[1])
        get_mail(sys.argv[1])
        print("处理文件完成：",sys.argv[1])
    elif len(sys.argv)==1:
        space()
    elif len(sys.argv)==3:
        if os.path.basename(sys.argv[1]).find(sys.argv[2])!=-1:
            print("正在处理文件：",sys.argv[1])
            get_mail(sys.argv[1])
            print("处理文件完成：",sys.argv[1])
        else:
            print("文件：",sys.argv[1],'未包含指定字符串：',sys.argv[2])
            return


if __name__ == "__main__":
    main()