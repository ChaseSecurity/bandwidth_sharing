import json
import pyshark
import sys
import os.path


def get_mail(file_name):
    json_file=open(file_name,'r')
    information_json=json.load(json_file)
    number_informations=information_json['number_informations']
    # base_time=information_json['base_time']
    filename=information_json['filename']
    # domain_ips=information_json['domain_ips']
    # ip_domains=information_json['ip_domains']
    # stream_ip_number=information_json['stream_ip_number']
    # stream_timestamp=information_json['stream_timestamp']  #这个是有减去basetime的
    # domain_streams=information_json['domain_streams']
    # stream_len=information_json['stream_len']
    # ip_domains_number=information_json['ip_domains_number']
    # stream_numbers=information_json['stream_numbers']
    # all_len=information_json['all_len']
    # all_base_tcp_len=information_json['all_base_tcp_len']


    files_path=[]
    server_information={}  #server_host -> ips_ports,ips,ports,from,to,from_to_content
    src_ips=['172.19.0.2','172.19.0.3','172.19.0.4']
    src_domains=['proxy.packetstream.io','api.packetstream.io','api.honeygain.com']
#0:src_ip  1:dst_ip     2:src_port    3:dst_port  4:length        5:stream       6:protocol    7:timestamp     8:host   9:_info


    #read old data
    try:
        input_json=open('mail.json','r')
        input_stat=json.load(input_json)
        server_information=input_stat['server_information']
        files_path=input_stat['files_path']
        input_json.close()
    except:
        print("没有json文件")

    if os.path.basename(filename) in files_path:
        print("该文件已经被处理过，跳过处理！")
        return 
    files_path.append(os.path.basename(filename))
    files_path.sort()

    stream_mail_information={}

    #deal with data
    for number,information in number_informations.items():
        if information[6]=='smtp':
            if information[5] not in stream_mail_information:
                stream_mail_information[information[5]]=['','',[],[]]
                if information[0] not in src_ips:
                    stream_mail_information[information[5]][0]=information[0]
                    stream_mail_information[information[5]][1]=information[2]
                else:
                    stream_mail_information[information[5]][0]=information[1]
                    stream_mail_information[information[5]][1]=information[3]
                stream_mail_information[information[5]][2]=[]
                if information[8]!='':
                    stream_mail_information[information[5]][2].append(information[8])
                
                stream_mail_information[information[5]][3].append(information[9])
            else:
                if information[8]!='':
                    stream_mail_information[information[5]][2].append(information[8])
                stream_mail_information[information[5]][3].append(information[9])


    for stream, mail_information in stream_mail_information.items():
        # deal with content
        phase=0
        k1=0
        k2=0
        host=''
        mail_from=''
        mail_to=''
        mail_content=''
        for msg in mail_information[3]:
            for key,contents in msg.items():
                for content in contents:
                    if phase==0:
                        if content.find('Response: 220')!=-1:
                            k0=content.find('Response: 220')
                            k1=content.find(' ',k0+13)
                            k2=content.find(' ',k1+1)
                            host=content[k1:k2]
                            phase+=1
                        
                            if host not in server_information:#server_host -> ips_ports,ips,ports,froms,tos,from_to_content,other_host,number
                                server_information[host]=[[],[],[],{},{},[],[],1]
                                server_information[host][0].append(mail_information[0])
                                server_information[host][1].append(mail_information[1])
                                server_information[host][2].append(mail_information[0]+":"+mail_information[1])
                            else:
                                server_information[host][7]+=1
                                if mail_information[0] not in server_information[host][0]:
                                    server_information[host][0].append(mail_information[0])
                                if mail_information[1] not in server_information[host][1]:
                                    server_information[host][1].append(mail_information[1])
                                if mail_information[0]+":"+mail_information[1] not in server_information[host][2]:
                                    server_information[host][2].append(mail_information[0]+":"+mail_information[1])
                    elif phase==1:
                        if content.find('MAIL FROM:<')!=-1:
                            k0=content.find('MAIL FROM:<')+11
                            k1=content.find('>')
                            mail_from=content[k0:k1]
                            if mail_from not in server_information[host][3]:
                                server_information[host][3][mail_from]=1
                            else:
                                server_information[host][3][mail_from]+=1
                            phase+=1
                    elif phase==2:
                        if content.find('RCPT TO:<')!=-1:
                            k0=content.find('RCPT TO:<')+9
                            k1=content.find('>')
                            mail_to=content[k0:k1]
                            if mail_to not in server_information[host][4]:
                                server_information[host][4][mail_to]=1
                            else:
                                server_information[host][4][mail_to]+=1
                            phase+=1
                    elif phase==3:
                        if content.find('DATA')!=-1:
                            phase+=1
                    elif phase==4:
                        #这个判断是否可以不要
                        if content.find('354')!=-1:
                            phase+=1
                    elif phase==5:
                        if content.find('250 OK')==-1:
                            mail_content+=content
                        else:
                            phase+=1
                    elif phase==6:
                        print('250 OK!')
                        
                #         print(content)
                # print("="*100)    
        # record content
        if mail_content !='':
            server_information[host][5].append([mail_from,mail_to,mail_content,filename])
    

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
    # write data
    output_stat={}
    output_stat['server_information']=server_information
    output_stat['files_path']=files_path
    
    output_json=open('mail.json','w')
    json.dump(output_stat, output_json)
    output_json.close()

def main():
    print("正在处理文件：",sys.argv[1])
    get_mail(sys.argv[1])
    print("处理文件完成：",sys.argv[1])


if __name__ == "__main__":
    main()
