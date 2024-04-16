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
        # smtp_stream=input_stat['smtp_stream']
        server_information=input_stat['server_information']
    except:
        print("没有read.json文件")
        return

    receiver_address=set([])
    try:
        input_json=open('receiver.json','r')
        input_stat=json.load(input_json)
        receiver_address=set(input_stat['receiver_address'])
        src_mail_suffix=input_stat['src_mail_suffix']
        dst_mail_suffix=input_stat['dst_mail_suffix']
        
    except:
        print("没有receiver.json文件")
        
    print("原来接收方邮箱个数:",len(receiver_address))
    used=len(receiver_address)

    for server,information in server_information.items():
        for i in range(len(information[5])):
            if information[5][i][5]>5:
                receiver_address.update(tuple(information[5][i][1]))

    print("接收方邮箱个数:",len(receiver_address))
    print('增加了:',len(receiver_address)-used)
    

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
    output_stat['receiver_address']=list(receiver_address)
    output_stat['src_mail_suffix']=src_mail_suffix
    output_stat['dst_mail_suffix']=dst_mail_suffix
    output_json=open('receiver.json','w')

    json.dump(output_stat, output_json)
    output_json.close()

if __name__ =='__main__':
    space()
