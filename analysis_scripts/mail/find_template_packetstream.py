import json
import pyshark
import sys
import os.path


def get_mail():

    src_mail_suffix={}
    dst_mail_suffix={}
    src_mail_suffix_sort={}
    dst_mail_suffix_sort={}

    blocked_ips=[]

    files_path=[]
    server_information={}  #server_host -> ips_ports,ips,ports,from,to,from_to_content
    src_ips=['172.19.0.2','172.19.0.3','172.19.0.4']
    src_domains=['proxy.packetstream.io','api.packetstream.io','api.honeygain.com']
#0:src_ip  1:dst_ip     2:src_port    3:dst_port  4:length        5:stream       6:protocol    7:timestamp     8:host   9:_info
    templates_arr={}
    template_num={}
    # templates_arr["1"]=['We have attached your grant offer.','In order to get you back on track to go back to school.','Sometimes taking the right life path starts with one choice.']
    # template_num["1"]=0
    # templates_arr["2"]=['We\'ve attached a grant finances.','To get you on track and go back to school.','Taking the right life path starts with one choice.']
    # template_num["2"]=0
    # templates_arr["3"]=['We have attached a grant finances.','To get you on track and go back to school.','Taking the right life path starts with one choice.']
    # template_num["3"]=0
    # templates_arr["4"]=['We have attached a grant offer.','To get you on track and go back to school.','Taking the right life path starts with one choice.']
    # template_num["4"]=0
    # templates_arr["5"]=['We have attached your grant offer','To get you on track and go back to school.','Sometimes taking the right life path starts with one choice.']
    # template_num["5"]=0   
    # templates_arr["6"]=['I\'m contacting you because I\'m employing','It may be intuition, or just a hunch, but I just have a feeling you would','I have attached your invite, the password is']
    # template_num["6"]=0
    # templates_arr["7"]=['I need to bring on','You seem like a good choice','Your invite is attached, the password is']
    # template_num["7"]=0

    templates_arr["1"]=list(set([
        'We have attached your grant offer',
        'We\\\'ve attached a grant offer',
        'We have attached a grant offer',
        'We\\\'ve attached your grant finances',
        'We\\\'ve attached a grant finances',
        'We have attached a grant finances',
        'We\\\'ve attached your grant offer',
        'We have attached your grant finances',
        


        'To get you back on track and go back to school.',
        'To get you back on track to go back to school.',
        'To get you on track and go back to school.',
        'In order to get you back on track to go back to school.',
        # 'In order to get you on track and go back to school.',
        'To get you on track to go back to school.',
        'In order to get you back on track and go back to school.',
        # 'In order to get you on track to go back to school.',
        'In order to get you on track',
        'in order to get you',
        'to get you on track',
        

        'Sometimes taking the right life path',
        'Taking the right life path',
        
        '=0D=0A',
    ]))
    template_num["1"]=[0,0]

    templates_arr["2"]=list(set([
        # 'I\'m contacting you because I\'m employing',
        # 'I\'m contacting you because I am employing',
        'I\\\'m contacting you',
        'I need to bring on',
        

        'You seem like a good choice',
        'You seem like a good candidate',
        'You seem like a great fit',
        'You seem like a good fit',
        'You seem like a great candidate',
        'It may be just a hunch',
        'It may be intuition',
        'I decided to toss you an invite',
        'you would be great for it',
        

        # 'I have attached your invite, the password is',
        # 'I have attached your invitation, the password is',
        'Your invite is',
        # 'Your invite is attached, the password is',
        'Your invitation is attached, the password is',
        # 'The invitation is attached, the password is',
        # 'I\'ve attached your invitation, the password is',
        # 'I\'ve attached your invite, the password is',
        # 'The invite is attached, the password is',
        # 'Your invite is attached, the password is',
        # 'I\'ve attached your secure invitation, the password is',
        # 'I have attached your secure invite, the password is',
        # 'I\'ve attached your secure invite, the password is',
        # 'I have attached your secure invitation, the password is',
        'The invitati',
        'The invite is',
        'I\\\'ve attache',
        'I have attache',
        'It\\\'s attach',
        'attached your',
        'The=\\r\\n invitation is attached',

        '=0D=0A',
        # '=0D=0A   =0D=0A',
        # '=0D=0A  =0D=0A',
        # '=0D=0A =0D=0A'
    ]))
    template_num["2"]=[0,0]

    templates_arr["3"]=list(set([
        'You may be entitled to',

        'Companies need to be',

        'I\\\'ve attached details for your case',

        '=0D=0A',
    ]))
    template_num["3"]=[0,0]

    templates_arr["4"]=list(set([
        'are your working',

        'Are you looking for',
        'Are you searching for',
        'Are you trying to',

        'Do you have a',
        'Have you got a',
        
    ]))
    template_num["4"]=[0,0]

    # templates_arr["5"]=list(set([
    #     'Companies need to',


    #     'Are you trying to',

    #     'Do you have a',
    #     'Have you got a',
    # ]))
    # template_num["5"]=0
    #read old data
    try:
        input_json=open('read.json','r')
        input_stat=json.load(input_json)
        server_information=input_stat['server_information']
        files_path=input_stat['files_path']
        input_json.close()
    except:
        print("没有json文件")
    #deal with data
    

    for server,information in server_information.copy().items():
        list_1 = list(information[3].items())
        mail_from_sort= dict(sorted(list_1,key = lambda x:x[1],reverse= True))

        list_2 = list(information[4].items())
        mail_to_sort= dict(sorted(list_2,key = lambda x:x[1],reverse= True))

        server_information[server][3]=mail_from_sort
        server_information[server][4]=mail_to_sort


        for i in range(len(information[5])):
            if information[5][i][5]>5:
                from_mail=information[5][i][0]
                num=1
        # for from_mail,num in information[3].items():
                if from_mail.find('@') !=-1:
                    if from_mail[from_mail.find('@')+1:] not in src_mail_suffix:
                        src_mail_suffix[from_mail[from_mail.find('@')+1:]]=[num,{}]
                        src_mail_suffix[from_mail[from_mail.find('@')+1:]][1][from_mail]=num
                    else:
                        if from_mail not in src_mail_suffix[from_mail[from_mail.find('@')+1:]][1]:
                            src_mail_suffix[from_mail[from_mail.find('@')+1:]][1][from_mail]=num
                        else:
                            src_mail_suffix[from_mail[from_mail.find('@')+1:]][1][from_mail]+=num
                        src_mail_suffix[from_mail[from_mail.find('@')+1:]][0]+=num
        
                for to_mail in information[5][i][1]:

        # for to_mail,num in information[4].items():
                    if to_mail[to_mail.find('@')+1:] not in dst_mail_suffix:
                            dst_mail_suffix[to_mail[to_mail.find('@')+1:]]=[num,{}]
                            dst_mail_suffix[to_mail[to_mail.find('@')+1:]][1][to_mail]=num
                    else:
                        if to_mail not in dst_mail_suffix[to_mail[to_mail.find('@')+1:]][1]:
                            dst_mail_suffix[to_mail[to_mail.find('@')+1:]][1][to_mail]=num
                        else:
                            dst_mail_suffix[to_mail[to_mail.find('@')+1:]][1][to_mail]+=num
                        dst_mail_suffix[to_mail[to_mail.find('@')+1:]][0]+=num

    list_3 = list(src_mail_suffix.items())
    src_mail_suffix_sort= dict(sorted(list_3,key = lambda x:x[1][0],reverse= True))
    list_4 = list(dst_mail_suffix.items())
    dst_mail_suffix_sort= dict(sorted(list_4,key = lambda x:x[1][0],reverse= True))


    for server,information in src_mail_suffix_sort.copy().items():
        list_1 = list(information[1].items())
        mail_from_sort= dict(sorted(list_1,key = lambda x:x[1],reverse= True))
        src_mail_suffix_sort[server][1]=mail_from_sort

    for server,information in dst_mail_suffix_sort.copy().items():
        list_1 = list(information[1].items())
        mail_to_sort= dict(sorted(list_1,key = lambda x:x[1],reverse= True))
        dst_mail_suffix_sort[server][1]=mail_to_sort


    src_suf_txt=open('src_suffix.txt','w')
    for mail_suffix,information in src_mail_suffix_sort.items():
        src_suf_txt.write(mail_suffix+","+str(information[0])+"\n")
        i=0
        for mail_name,num in information[1].items():
            i+=1
            if i==11:
                break
            src_suf_txt.write("\t"+mail_name+","+str(num)+"\n")
        src_suf_txt.write("\n")
    src_suf_txt.close()

    dst_suf_txt=open('dst_suffix.txt','w')
    for mail_suffix,information in dst_mail_suffix_sort.items():
        dst_suf_txt.write(mail_suffix+",总接收方邮箱个数:"+str(information[0])+",去掉重复后:"+str(len(information[1]))+"\n")
        i=0
        for mail_name,num in information[1].items():
            i+=1
            if i==11:
                break
            dst_suf_txt.write("\t"+mail_name+","+str(num)+"\n")
        dst_suf_txt.write("\n")
    dst_suf_txt.close()

    others_txt=open('others.txt','w')
    block_txt=open('block.txt','w')
    others_num=0
    send_sussess_num=0
    send_no_success_num=0
    error_1=0
    error_2=0
    error_3=0
    error_4=0
    error_5=0
    error_6=0
    for server,information in server_information.items():
        for i in range(len(information[5])):
            if information[5][i][5]>5:
                #阻塞原因
                k0=information[5][i][2].find('\\r\\n.\\r\\n')
                if information[5][i][2][k0+9:k0+13]!='250 ':
                    if information[5][i][2].find('Our system has detected an unusual rate of')!=-1:
                        error_1+=1
                    elif  information[5][i][2].find('Our system has detected that this message is')!=-1:
                        error_2+=1
                    elif  information[5][i][2].find('This message does not pass authentication checks')!=-1:
                        error_3+=1
                    elif  information[5][i][2].find('This message does not have authentication')!=-1:
                        error_4+=1
                    elif  information[5][i][2].find('This message fails to pass SPF checks for an SPF record')!=-1:
                        error_5+=1
                    else:
                        block_txt.write(information[5][i][2][k0+9:]+"\n")
                    send_no_success_num+=1
                else:
                    send_sussess_num+=1
                is_template=False
                have_0D0A=False
                if information[5][i][2].find('=0D=0A')!=-1:
                    have_0D0A=True
                for no,templates in templates_arr.items():
                    true_num=0
                    for template in templates:
                        if information[5][i][2].find(template)!=-1:
                            true_num+=1
                    if true_num>=3:
                        template_num[no][0]+=1
                        if have_0D0A:
                            template_num[no][1]+=1
                        is_template=True
                        break
                if not is_template:
                    others_num+=1
                    others_txt.write(information[5][i][3]+"\n")
                    others_txt.write(information[5][i][4]+"\n\n")
        
            # find blocked ip
            if information[5][i][2].find('Response: 550-5.7.1 [') !=-1:
                k1=information[5][i][2].find('Response: 550-5.7.1 [')
                k2=information[5][i][2].find(']')
                #print(information[5][i][2][k1+21:k2])
                if information[5][i][2][k1+21:k2] not in blocked_ips:
                    blocked_ips.append(information[5][i][2][k1+21:k2])
                
    others_txt.close()
    blocked_ips.sort()
    blocked_ip_txt=open('blocked_ips.txt','w')
    for ip in blocked_ips:
        blocked_ip_txt.write(ip+"\n")
    blocked_ip_txt.close()
    # others_txt=open('others.txt','w')
    
    # for server,information in server_information.items():
    #     for i in range(len(information[5])):
    #         # if information[5][i][2].find('We have attached your grant offer.\\r\\n\n        \\r\\n\n        In order to get you back on track to go back to school.\\r\\n\n        \\r\\n\n        Sometimes taking the right life path starts with one choice.\\r\\n\n') !=-1:
    #         #     print("1")
    #         # if information[5][i][2].find('We have attached your grant offer.\\r\\n')!=-1:
    #         #     print("2")
    #         # if information[5][i][2].find('We have attached your grant offer.\\r\\n\t')!=-1:
    #         #     print("3")
    #         is_template=True
    #         for no,templates in templates_arr.items():
    #             is_template=True
    #             for template in templates:
    #                 if information[5][i][2].find(template)==-1:
    #                     is_template=False
    #                     break
    #             if is_template:
    #                 template_num[no]+=1
    #                 break
    #         if not is_template:
    #             others_txt.write(information[5][i][2]+"\n")
    # others_txt.close()

    for no,num in template_num.items():
        print(no+","+str(num[0])+","+"有0D0A的个数:"+str(num[1]))
    print('non-template:',others_num)
    print('发送成功的数量:',send_sussess_num)
    print('发送失败的数量:',send_no_success_num)
    print('e1:',error_1)
    print('e2:',error_2)
    print('e3:',error_3)
    print('e4:',error_4)
    print('e5:',error_5)

def main():
    print("正在处理")
    get_mail()
    print("处理完成")


if __name__ == "__main__":
    main()
