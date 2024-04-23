import dpkt
import sys
import socket
import json
import struct
import os
import re


def space():

    src_mail_suffix={}
    dst_mail_suffix={}
    src_mail_suffix_sort={}
    dst_mail_suffix_sort={}
    try:
        input_json=open('read.json','r')
        input_stat=json.load(input_json)
        # files_path=input_stat['files_path']
        # all_tcp_len=input_stat['all_tcp_len']
        # smtp_len=input_stat['smtp_len']
        # all_stream=input_stat['all_stream']
        smtp_stream=input_stat['smtp_stream']
        server_information=input_stat['server_information']
    except:
        print("没有read.json文件")
        return

    receiver_address_success={}
    sender_address_success={}
    receiver_address_all={}
    sender_address_all={}
    message_num=0
    message_success_num=0
    flow_no_ehlo=0
    flow_no_rcpt=0
    smtp_flow=0
    sendSuccess_server=[]
    sendSuccess_recipient=0

    all_server=[]
    # senderSuccess_subject_emailCount_recipients={}
    try:
        input_json=open('receiver.json','r')
        input_stat=json.load(input_json)
        receiver_address_success=input_stat['receiver_address_success']
        sender_address_success=input_stat['sender_address_success']
        receiver_address_all=input_stat['receiver_address_all']
        sender_address_all=input_stat['sender_address_all']
        src_mail_suffix=input_stat['src_mail_suffix']
        dst_mail_suffix=input_stat['dst_mail_suffix']
        # senderSuccess_subject_emailCount_recipients=input_stat['senderSuccess_subject_emailCount_recipients']
        message_num=input_stat['message_num']
        message_success_num=input_stat['message_success_num']
        flow_no_ehlo=input_stat['flow_no_ehlo']
        flow_no_rcpt=input_stat['flow_no_rcpt']
        smtp_flow=input_stat['smtp_flow']
        sendSuccess_server=input_stat['sendSuccess_server']
        sendSuccess_recipient=input_stat['sendSuccess_recipient']
        all_server=input_stat['all_server']
    except:
        print("没有receiver.json文件")
    
    smtp_flow+=smtp_stream
    print("原来接收方邮箱个数:",len(receiver_address_success))
    # used=len(receiver_address_success)

    need_sender=['newsletter@brosskled.com','newsletter@navydatic.com','newsletter@vollphy.com','newsletter@tupejoy.com','newsletter@vimkled.com']


    for server,information in server_information.items():
        s1=server[:server.rfind('.')]
        s2=s1[s1.rfind('.')+1:]
        host=s2+server[server.rfind('.'):]
        # sender%_template%_emai%l_recipients%
        
        if host.find('.')!=-1 and host not in all_server:
            all_server.append(host)



        for mail_from,num in information[3].items():
            if mail_from not in sender_address_all:
                sender_address_all[mail_from]=1
            else:
                sender_address_all[mail_from]+=1
        for mail_to,num in information[4].items():
            if mail_to not in sender_address_all:
                receiver_address_all[mail_to]=1
            else:
                receiver_address_all[mail_to]+=1
        for i in range(len(information[5])):
            # if information[5][i][0] in need_sender:
            #     if information[5][i][0] not in senderSuccess_subject_emailCount_recipients:
            #         senderSuccess_subject_emailCount_recipients[information[5][i][0]]=[[],1,information[5][i][1]]



            # if information[5][i][5]>5:
            #     if information[5][i][0] not in senderSuccess_subject_emailCount_recipients:
            #         senderSuccess_subject_emailCount_recipients[information[5][i][0]]=[[subject],1,information[5][i][1]]
            #     else:
            #         if subject not in senderSuccess_subject_emailCount_recipients[information[5][i][0]][0]:
            #             senderSuccess_subject_emailCount_recipients[information[5][i][0]][0].append(subject)
            #         senderSuccess_subject_emailCount_recipients[information[5][i][0]][1]+=1
            #         for mail_to in information[5][i][1]:
            #             if mail_to not in senderSuccess_subject_emailCount_recipients[information[5][i][0]][2]:
            #                 senderSuccess_subject_emailCount_recipients[information[5][i][0]][2].append(mail_to)
            ############4
            if information[5][i][5]==7:
                if host not in sendSuccess_server and host.find('.')!=-1:
                    sendSuccess_server.append(host)
                sendSuccess_recipient+=len(information[5][i][1])

            ############3
            if information[5][i][5]<=1:
                flow_no_ehlo+=1
            if information[5][i][5]<=3:
                flow_no_rcpt+=1

            
            if information[5][i][5]>5:
                message_num+=1

            if information[5][i][5]==7:
                message_success_num+=1
                # receiver_address_success.update(tuple(information[5][i][1]))
                for mail_to in information[5][i][1]:
                    if mail_to not in receiver_address_success:
                        receiver_address_success[mail_to]=1
                    else:
                        receiver_address_success[mail_to]+=1
                if information[5][i][0] not in sender_address_success:
                    sender_address_success[information[5][i][0]]=1
                else:
                    sender_address_success[information[5][i][0]]+=1

    # print("接收方邮箱个数:",len(receiver_address_success))
    # print('增加了:',len(receiver_address_success)-used)
    

    for server,information in server_information.copy().items():
        list_1 = list(information[3].items())
        mail_from_sort= dict(sorted(list_1,key = lambda x:x[1],reverse= True))

        list_2 = list(information[4].items())
        mail_to_sort= dict(sorted(list_2,key = lambda x:x[1],reverse= True))

        server_information[server][3]=mail_from_sort
        server_information[server][4]=mail_to_sort


        # for i in range(len(information[5])):
        #     if information[5][i][5]>5:
        #         from_mail=information[5][i][0]
        #         num=1
        for from_mail,num in information[3].items():
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
        
                # for to_mail in information[5][i][1]:

        for to_mail,num in information[4].items():
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


    src_suf_txt=open('new_src_suffix.txt','w')
    print('src fqdn count:',len(src_mail_suffix_sort))
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

    dst_suf_txt=open('new_dst_suffix.txt','w')
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

    output_stat={}
    output_stat['receiver_address_success']=receiver_address_success
    output_stat['sender_address_success']=sender_address_success
    output_stat['sender_address_all']=sender_address_all
    output_stat['receiver_address_all']=receiver_address_all
    output_stat['src_mail_suffix']=src_mail_suffix
    output_stat['dst_mail_suffix']=dst_mail_suffix
    output_stat['message_num']=message_num
    output_stat['message_success_num']=message_success_num
    output_stat['flow_no_ehlo']=flow_no_ehlo
    output_stat['flow_no_rcpt']=flow_no_rcpt
    output_stat['smtp_flow']=smtp_flow
    output_stat['sendSuccess_recipient']=sendSuccess_recipient
    output_stat['sendSuccess_server']=sendSuccess_server
    output_stat['all_server']=all_server
    
    # output_stat['senderSuccess_subject_emailCount_recipients']=senderSuccess_subject_emailCount_recipients
    
    output_json=open('receiver.json','w')

    json.dump(output_stat, output_json)
    output_json.close()

    one_times=0
    five_times=0
    ten_times=0
    other_times=0
    all_receiver_num=len(receiver_address_success)
    for receiver,number in receiver_address_success.items():
        if number==1:
            one_times+=1
        elif 1<number<=5:
            five_times+=1
        elif 5<number<=10:
            ten_times+=1
        else:
            other_times+=1
    
    print('one_times:',round(100*one_times/all_receiver_num,2),one_times)
    print('five_times:',round(100*five_times/all_receiver_num,2),five_times)
    print('ten_times:',round(100*ten_times/all_receiver_num,2),ten_times)
    print('other_times:',round(100*other_times/all_receiver_num,2),other_times)

    print('sender_address_all:',len(sender_address_all))
    print('receiver_address_all:',len(receiver_address_all))
    print('message_num:',message_num)
    print('message_success_num:',message_success_num)


    print('flow_no_ehlo',flow_no_ehlo,flow_no_ehlo/smtp_flow)
    print('flow_no_rcpt',flow_no_rcpt,flow_no_rcpt/smtp_flow)
    # print('sendSuccess_server:',sendSuccess_server)
    print('sendSuccess_recipient:',sendSuccess_recipient)
    print('sendSuccess_server:',len(sendSuccess_server))
    print('all_server:',len(all_server))

    list_3 = list(sender_address_all.items())
    ssender_address_all_sort= dict(sorted(list_3,key = lambda x:x[1],reverse= True))
    i=0
    for  sender,num in  ssender_address_all_sort.items():
        i+=1
        if i<=5:
            print(sender,num)

if __name__ =='__main__':
    space()
