import json
import os
import sys
import shutil

source_pcap_dir=''
output_split_dir=''
#label 0,1

def split_pcap(filename):

    files_path=[]
    #read old data
    try:
        input_json=open('stat.json','r')
        input_stat=json.load(input_json)
        # all_base_tcp_len+=input_stat['all_base_tcp_len']
        
        files_path=input_stat['files_path']
        input_json.close()
    except:
        print("没有json文件")

    if os.path.basename(filename) in files_path:
        print("该文件已经被处理过，跳过处理！")
        exit()
    files_path.append(os.path.basename(filename))
    files_path.sort()

    in_file=open(filename,'r')
    i=0
    for line in in_file.readlines():
        i+=1
        if i<100:  #前面连接的包可能不完整，不用
            continue
        line=line.strip()
        stat=json.loads(line)
        if stat[6]=='tcp':
            copy_filename=stat[8]+".TCP_"+stat[1].replace('.','-')+'_'+str(stat[2])+'_'+stat[3].replace('.','-')+'_'+str(stat[4])+'.pcap'
            copy_from=source_pcap_dir+'/'+stat[8]+'/'+copy_filename
            if stat[0]==1:
                copy_to=output_split_dir+'/1/'+copy_filename     
            elif stat[0]==0:
                copy_to=output_split_dir+'/0/'+copy_filename
            try:
                shutil.copy(copy_from,copy_to)
            except:
                copy_filename=stat[8]+".TCP_"+stat[3].replace('.','-')+'_'+str(stat[4])+'_'+stat[1].replace('.','-')+'_'+str(stat[2])+'.pcap'
                copy_from=source_pcap_dir+'/'+stat[8]+'/'+copy_filename
                if stat[0]==1:
                    copy_to=output_split_dir+'/1/'+copy_filename     
                elif stat[0]==0:
                    copy_to=output_split_dir+'/0/'+copy_filename
                try:
                    shutil.copy(copy_from,copy_to)
                except:
                    print('两个文件都没有？！')

    output_stat={}
    # output_stat['all_len']=all_len
    # output_stat['all_base_tcp_len']=all_base_tcp_len
    output_stat['files_path']=files_path

    output_json=open('stat.json','w')
    json.dump(output_stat, output_json)
    output_json.close()



def main():
    if not os.path.exists(output_split_dir+'/0/'):
        os.makedirs(output_split_dir+'/0/')
    if not os.path.exists(output_split_dir+'/1/'):
        os.makedirs(output_split_dir+'/1/')

    print('正在处理文件:',sys.argv[1])
    split_pcap(sys.argv[1])
    print('处理文件完成:',sys.argv[1])

if __name__ == "__main__":
    main()
