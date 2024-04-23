import sys
import json
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.metrics import confusion_matrix
from sklearn.metrics import accuracy_score
import joblib
import numpy as np
import tqdm
import os
import dpkt
import socket
import time
import random

pcap_path="/path/to/pcap/"  # 分割0 1 的地方
dataset_path='/path/to/dataset/'
model_path='/path/to/model/'

class JsonEncoder(json.JSONEncoder):
    """Convert numpy classes to JSON serializable objects."""

    def default(self, obj):
        if isinstance(obj, (np.integer, np.floating, np.bool_)):
            return obj.item()
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        else:
            return super(JsonEncoder, self).default(obj)

def generation(pcap_path,dataset_path):
    dataset = {}
    X=[]
    Y=[]
    providers = []  
    label_name_list = []

    session_pcap_path  = {}

    provider_number=[{},{}]
    provider_list=['packetstream','honeygain','iproyal']  
    provider_number[0]['packetstream']=0
    provider_number[0]['honeygain']=0
    provider_number[0]['iproyal']=0
    provider_number[0]['others_dataset']=0
    provider_number[1]['packetstream']=0
    provider_number[1]['honeygain']=0
    provider_number[1]['iproyal']=0
    provider_number[1]['others_dataset']=0


    for parent, dirs, files in os.walk(pcap_path):
        if label_name_list == []:
            label_name_list.extend(dirs)

        # print('label_name_list:',label_name_list)
        for dir in label_name_list:
            for p,dd,ff in os.walk(parent + "/" + dir):
                session_pcap_path[dir] = pcap_path + dir
        break
    print('session_pcap_path:',session_pcap_path)
    for key in tqdm.tqdm(session_pcap_path.keys()):
        target_all_files = [x[0] + "/" + y for x in [(p, f) for p, d, f in os.walk(session_pcap_path[key])] for y in x[1]]
        r_files = target_all_files
        for r_f in r_files:

            print('正在处理:',r_f)
            feature_data = get_feature_flow(r_f)
            if feature_data==-1:
                print('处理完成:',r_f)
                continue
        

            found=False
            for provider in provider_list:
                if r_f.find(provider)!=-1:
                    found=True
                    provider_number[int(key)][provider]+=1
                    break
            if not found:
                provider_number[int(key)]['others_dataset']+=1
            providers.append(provider if found else 'others_dataset')  
            X.append(feature_data)
            Y.append(int(key))
            print('处理完成:',r_f)
        dataset['providers'] = providers  
    print('other dataset:')
    for provider,number in provider_number[0].items():   
        print(provider+": ",number)

    print('relayed dataset:')
    for provider,number in provider_number[1].items():
        print(provider+": ",number)
    print('dataset: ',dataset_path+'dataset.json')

    dataset['X']=X
    dataset['Y']=Y
    dataset['provider_number']=provider_number
    dataset_file=open(dataset_path+'dataset.json','w')
    json.dump(dataset,dataset_file,ensure_ascii=False, cls=JsonEncoder)


def get_feature_flow(filename):
    try:
        data_output={}
        data_output['upstreamRatio']=[]
        ##  profile the inter-packet arrival time for upstream traffic of a given flow
        data_output['uploadPacket']=[]
        data_output['downloadPacket']=[]
        data_output['interPacket']=[]

        ##  bytes_per_second_
        data_output['bytes_per_second_uploadPacket']=[]
        data_output['bytes_per_second_downloadPacket']=[]
        data_output['bytes_per_second_interPacket']=[]

        ##  packets_per_second_
        data_output['packets_per_second_uploadPacket']=[]
        data_output['packets_per_second_downloadPacket']=[]
        data_output['packets_per_second_interPacket']=[]

        ### size
        data_output['size_uploadPacket']=[]
        data_output['size_downloadPacket']=[]
        data_output['size_interPacket']=[]
        
        

        f=open(filename,'rb')
        try:
            pcap = dpkt.pcap.Reader(f)
        except:
            # f2.write(filename+"\n")
            print(filename)
            return -1
        
        seq0=0
        ack0=0

        packet_num=0    #当前pcap数据包 number
        upload_num=0
        download_num=0

        last_packet_ts=0
        last_upload_ts=0
        last_download_num=0

        upload_packets_ts=[]
        download_packets_ts=[]
        inter_packets_ts=[]

        upload_packets_bytes=[]
        download_packets_bytes=[]
        inter_packets_bytes=[]

        upload_packets_delta_ts=[]
        download_packets_delta_ts=[]
        inter_packets_delta_ts=[]

        upload_packets_total_bytes=[]
        download_packets_total_bytes=[]
        inter_packets_total_bytes=[]

        need_num=[2,4,8,16,32,64] 
        need_length=6
        max_need_num=max(need_num)
        find_src_ip=False

        total_upstream = 0  # 初始化变量
        total_downstream = 0  # 初始化变量

        for ts,buf in pcap:

            buf_length=len(buf)
            packet_num+=1

            # if packet_num not in need_num:
            #     continue
        #make sure we are dealing with IP traffic
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except:
                print('no!!!')
                # f2.write(filename+"\n")
                return -1
            try:
                if eth.type != 2048:
                    ip=dpkt.ip.IP(buf)
                else:
                    ip = eth.data
            except:
                # f2.write(filename+"\n")
                print(filename)
                return -1
            sip=socket.inet_ntoa(ip.src)
            dip=socket.inet_ntoa(ip.dst)

            if packet_num==1:
                src_ip=sip

            if sip == src_ip:
                upload_num+=1
                upload_packets_ts.append(ts)
                upload_packets_bytes.append(buf_length)
            else:
                download_num+=1
                download_packets_ts.append(ts)
                download_packets_bytes.append(buf_length)
            inter_packets_ts.append(ts)
            inter_packets_bytes.append(buf_length)
            if upload_num>max_need_num and download_num>max_need_num:
                break
            #ip.src  ip.dst
            if ip.p == 17:  # UDP协议
                protocol = 'udp'
                udp = ip.data

                # 计算UDP数据包的有效载荷长度
                udp_payload_length = udp.ulen - 8  # UDP头部固定长度为8字节

                if sip == src_ip:
                    # 如果是上行数据包，更新上行总数据量
                    total_upstream += udp_payload_length
                else:
                    # 如果是下行数据包，更新下行总数据量
                    total_downstream += udp_payload_length

                if upload_num in need_num:
                    # 计算上行比率
                    if total_upstream + total_downstream > 0:
                        upstream_ratio = total_upstream / (total_upstream + total_downstream)
                        data_output['upstreamRatio'].append(upstream_ratio)
                    
                
            elif ip.p==6:
                protocol='tcp'
                tcp= ip.data
                if packet_num==1:
                    if tcp.flags==2:
                        seq0=tcp.seq  #本方发送syn，本方的seq是本方的seq
                    else:
                        print("**error** : the first packet is not syn")
                        return -1
                elif packet_num==2:
                    if tcp.flags==18:
                        ack0=tcp.seq  #对方的seq是本方的ack
                    else:
                        print("**error** : the second packet is not syn_ack")
                        return -1
                

                if upload_num in need_num and sip==src_ip:
                    delta_seq=tcp.seq-seq0
                    delta_ack=tcp.ack-ack0
                    upstreamRatio=delta_seq/(delta_seq+delta_ack)
                    data_output['upstreamRatio'].append(upstreamRatio)

        # 取delta
        for i in range(1,len(upload_packets_ts)):
            upload_packets_delta_ts.append(upload_packets_ts[i]-upload_packets_ts[i-1])

        for i in range(1,len(download_packets_ts)):
            download_packets_delta_ts.append(download_packets_ts[i]-download_packets_ts[i-1])

        for i in range(1,len(inter_packets_ts)):
            inter_packets_delta_ts.append(inter_packets_ts[i]-inter_packets_ts[i-1])

        ##每个下标代表前i个包的字节数总和
        for i in range(1,len(upload_packets_bytes)):
            upload_packets_total_bytes.append(sum(upload_packets_bytes[0:i]))  
        for i in range(1,len(download_packets_ts)):
            download_packets_total_bytes.append(sum(download_packets_bytes[0:i]))  
        for i in range(1,len(inter_packets_ts)):
            inter_packets_total_bytes.append(sum(inter_packets_bytes[0:i]))  


        # print(len(upload_packets_ts),src_ip)
        if len(upload_packets_delta_ts)==0 or len(download_packets_delta_ts)==0 or len(inter_packets_delta_ts)==0:
            print('**error** : data no enough ---1 ! ', os.path.getsize(filename))
            return -1

        ### 1
        for i in need_num:
            max_=np.max(upload_packets_delta_ts[0:i-1])
            min_=np.min(upload_packets_delta_ts[0:i-1])
            mean_=np.mean(upload_packets_delta_ts[0:i-1])
            std_=np.std(upload_packets_delta_ts[0:i-1])
            data_output['uploadPacket'].append([mean_,max_,min_,std_])

        for i in need_num:
            max_=np.max(download_packets_delta_ts[0:i-1])
            min_=np.min(download_packets_delta_ts[0:i-1])
            mean_=np.mean(download_packets_delta_ts[0:i-1])
            std_=np.std(download_packets_delta_ts[0:i-1])
            data_output['downloadPacket'].append([mean_,max_,min_,std_])

        for i in need_num:
            max_=np.max(inter_packets_delta_ts[0:i-1])
            min_=np.min(inter_packets_delta_ts[0:i-1])
            mean_=np.mean(inter_packets_delta_ts[0:i-1])
            std_=np.std(inter_packets_delta_ts[0:i-1])
            data_output['interPacket'].append([mean_,max_,min_,std_])

        ### 2,3
        # print(len(upload_packets_total_bytes))
        for i in need_num:
            if i>len(upload_packets_total_bytes):
                break
            data_output['bytes_per_second_uploadPacket'].append(upload_packets_total_bytes[i-1]/(upload_packets_ts[i-1]-upload_packets_ts[0]))
            data_output['packets_per_second_uploadPacket'].append(i/(upload_packets_ts[i-1]-upload_packets_ts[0]))
        for i in need_num:
            if i>len(download_packets_total_bytes):
                break
            data_output['bytes_per_second_downloadPacket'].append(download_packets_total_bytes[i-1]/(download_packets_ts[i-1]-download_packets_ts[0]))
            data_output['packets_per_second_downloadPacket'].append(i/(download_packets_ts[i-1]-download_packets_ts[0]))
        for i in need_num:
            if i>len(inter_packets_total_bytes):
                break
            data_output['bytes_per_second_interPacket'].append(inter_packets_total_bytes[i-1]/(inter_packets_ts[i-1]-inter_packets_ts[0]))
            data_output['packets_per_second_interPacket'].append(i/(inter_packets_ts[i-1]-inter_packets_ts[0]))
        
        ### 4
        for i in need_num:
            max_=np.max(upload_packets_bytes[0:i])
            min_=np.min(upload_packets_bytes[0:i])
            mean_=np.mean(upload_packets_bytes[0:i])
            std_=np.std(upload_packets_bytes[0:i])
            data_output['size_uploadPacket'].append([mean_,max_,min_,std_])

        for i in need_num:
            max_=np.max(download_packets_bytes[0:i])
            min_=np.min(download_packets_bytes[0:i])
            mean_=np.mean(download_packets_bytes[0:i])
            std_=np.std(download_packets_bytes[0:i])
            data_output['size_downloadPacket'].append([mean_,max_,min_,std_])

        for i in need_num:
            max_=np.max(inter_packets_bytes[0:i])
            min_=np.min(inter_packets_bytes[0:i])
            mean_=np.mean(inter_packets_bytes[0:i])
            std_=np.std(inter_packets_bytes[0:i])
            data_output['size_interPacket'].append([mean_,max_,min_,std_])

        

        if len(data_output['upstreamRatio'])==0:
            print("**error** : data don't enough ! ---2")
            return -1

        # 若不满足个数，用最后一个数据补全   得改
        if len(data_output['upstreamRatio'])<need_length:
            last_data=data_output['upstreamRatio'][len(data_output['upstreamRatio'])-1]
            for i in range(need_length-len(data_output['upstreamRatio'])):
                data_output['upstreamRatio'].append(last_data)

        if len(data_output['uploadPacket'])<need_length:
            last_data=data_output['uploadPacket'][len(data_output['uploadPacket'])-1]
            for packet_num in range(need_length-len(data_output['uploadPacket'])):
                data_output['uploadPacket'].append(last_data)

        if len(data_output['downloadPacket'])<need_length:
            last_data=data_output['downloadPacket'][len(data_output['downloadPacket'])-1]
            for packet_num in range(need_length-len(data_output['downloadPacket'])):
                data_output['downloadPacket'].append(last_data)

        if len(data_output['interPacket'])<need_length:
            last_data=data_output['interPacket'][len(data_output['interPacket'])-1]
            for packet_num in range(need_length-len(data_output['interPacket'])):
                data_output['interPacket'].append(last_data)

        ### 2,3
        if len(data_output['bytes_per_second_uploadPacket'])<need_length:
            if len(data_output['bytes_per_second_uploadPacket'])!=0:
                last_data=data_output['bytes_per_second_uploadPacket'][len(data_output['bytes_per_second_uploadPacket'])-1]
            else:
                last_data=0
            for i in range(need_length-len(data_output['bytes_per_second_uploadPacket'])):
                data_output['bytes_per_second_uploadPacket'].append(last_data)
        
        # print(filename,len(data_output['bytes_per_second_downloadPacket']))
        if len(data_output['bytes_per_second_downloadPacket'])<need_length:
            if len(data_output['bytes_per_second_downloadPacket'])!=0:
                last_data=data_output['bytes_per_second_downloadPacket'][len(data_output['bytes_per_second_downloadPacket'])-1]
            else:
                last_data=0

            for i in range(need_length-len(data_output['bytes_per_second_downloadPacket'])):
                data_output['bytes_per_second_downloadPacket'].append(last_data)

        if len(data_output['bytes_per_second_interPacket'])<need_length:
            if len(data_output['bytes_per_second_interPacket'])!=0:
                last_data=data_output['bytes_per_second_interPacket'][len(data_output['bytes_per_second_interPacket'])-1]
            else:
                last_data=0
            for i in range(need_length-len(data_output['bytes_per_second_interPacket'])):
                data_output['bytes_per_second_interPacket'].append(last_data)
        
        if len(data_output['packets_per_second_uploadPacket'])<need_length:
            if len(data_output['packets_per_second_uploadPacket'])!=0:
                last_data=data_output['packets_per_second_uploadPacket'][len(data_output['packets_per_second_uploadPacket'])-1]
            else:
                last_data=0
            for i in range(need_length-len(data_output['packets_per_second_uploadPacket'])):
                data_output['packets_per_second_uploadPacket'].append(last_data)
        
        if len(data_output['packets_per_second_downloadPacket'])<need_length:
            if len(data_output['packets_per_second_downloadPacket'])!=0:
                last_data=data_output['packets_per_second_downloadPacket'][len(data_output['packets_per_second_downloadPacket'])-1]
            else:
                last_data=0
            for i in range(need_length-len(data_output['packets_per_second_downloadPacket'])):
                data_output['packets_per_second_downloadPacket'].append(last_data)
                
        if len(data_output['packets_per_second_interPacket'])<need_length:
            if len(data_output['packets_per_second_interPacket'])!=0:
                last_data=data_output['packets_per_second_interPacket'][len(data_output['packets_per_second_interPacket'])-1]
            else:
                last_data=0
            for i in range(need_length-len(data_output['packets_per_second_interPacket'])):
                data_output['packets_per_second_interPacket'].append(last_data)

        ### 4
        if len(data_output['size_uploadPacket'])<need_length:
            last_data=data_output['size_uploadPacket'][len(data_output['size_uploadPacket'])-1]
            for packet_num in range(need_length-len(data_output['size_uploadPacket'])):
                data_output['size_uploadPacket'].append(last_data)

        if len(data_output['size_downloadPacket'])<need_length:
            last_data=data_output['size_downloadPacket'][len(data_output['size_downloadPacket'])-1]
            for packet_num in range(need_length-len(data_output['size_downloadPacket'])):
                data_output['size_downloadPacket'].append(last_data)

        if len(data_output['size_interPacket'])<need_length:
            last_data=data_output['size_interPacket'][len(data_output['size_interPacket'])-1]
            for packet_num in range(need_length-len(data_output['size_interPacket'])):
                data_output['size_interPacket'].append(last_data)
        

        output=[]
        for i in range(need_length):
            output.append(data_output['upstreamRatio'][i])
        for i in range(need_length):
            output.extend(data_output['uploadPacket'][i])
        for i in range(need_length):
            output.extend(data_output['downloadPacket'][i])
        for i in range(need_length):
            output.extend(data_output['interPacket'][i])
        
        ### 2
        # print(len(output))
        for i in range(need_length):
            output.append(data_output['bytes_per_second_uploadPacket'][i])
        for i in range(need_length):
            output.append(data_output['bytes_per_second_downloadPacket'][i])
        for i in range(need_length):
            output.append(data_output['bytes_per_second_interPacket'][i])   
        
        ### 3
        # print(len(output))
        for i in range(need_length):
            output.append(data_output['packets_per_second_uploadPacket'][i])
        for i in range(need_length):
            output.append(data_output['packets_per_second_downloadPacket'][i])
        for i in range(need_length):
            output.append(data_output['packets_per_second_interPacket'][i]) 

        ### 4
        for i in range(need_length):
            output.extend(data_output['size_uploadPacket'][i])
        for i in range(need_length):
            output.extend(data_output['size_downloadPacket'][i])
        for i in range(need_length):
            output.extend(data_output['size_interPacket'][i])
        
        # print(output)
        # print('='*100)
        return output
    except:
        return -1


def training(dataset_path, model_path):
    dataset_file = open(dataset_path + "dataset.json", 'r')
    dataset = json.load(dataset_file)
    X = dataset['X']
    y = dataset['Y']
    providers = dataset['providers']  # Get the providers from the dataset
    
    # Filter training data for training
    filter_providers = ['packetstream', 'iproyal', 'honeygain','others_dataset']
    # 定义要过滤的提供者和每个提供者的最大数据量
    max_samples_per_label = 2000

    # 过滤数据
    filtered_X = []
    filtered_y = []
    filtered_providers = []  # 更新providers列表
    provider_label_counts = {provider: {0: 0, 1: 0} for provider in filter_providers}
    for feature, label, provider in zip(X, y, providers):
        if provider in ['packetstream', 'iproyal', 'honeygain']:
            if provider_label_counts[provider][label] < max_samples_per_label:
                filtered_X.append(feature)
                filtered_y.append(label)
                filtered_providers.append(provider)  # Update the providers list
                provider_label_counts[provider][label] += 1
        elif provider == 'others_dataset':
            filtered_X.append(feature)
            filtered_y.append(label)
            filtered_providers.append(provider)  # Add others_dataset provider without filtering
        else:
            filtered_X.append(feature)
            filtered_y.append(label)
            filtered_providers.append(provider)  # Update the providers list

    
    
    X = filtered_X
    y = filtered_y
    providers = filtered_providers

    # Split the data into training and test sets (80:20)
    X_train, X_test, y_train, y_test, providers_train, providers_test = train_test_split(X, y, providers, test_size=0.2, random_state=42)

    


    X_train_filtered, y_train_filtered = zip(*[(x, label) for x, label, provider in zip(X_train, y_train, providers_train) if provider in filter_providers])

    # Train the model on filtered training data
    clf = RandomForestClassifier(n_estimators=10)
    clf = clf.fit(X_train_filtered, y_train_filtered)
    joblib.dump(clf, model_path + 'relayed_2.pkl')

    # Test the model on all test data
    print('\n\n\n'+'='*20)
    print("Metrics for all test data:")
    y_pred_all = clf.predict(X_test)
    calculate_metrics(y_test, y_pred_all)
    print("Incorrect predictions for all test data:")
    analyze_predictions(y_test, y_pred_all, providers_test)

    # Test the model on test data with only the first three providers
    X_test_first_three, y_test_first_three, providers_test_first_three = zip(*[(x, label, provider) for x, label, provider in zip(X_test, y_test, providers_test) if provider in filter_providers])
    print('\n\n\n'+'='*20)
    print("Metrics for test data with only the first three providers:")
    y_pred_first_three = clf.predict(X_test_first_three)
    calculate_metrics(y_test_first_three, y_pred_first_three)
    print("Incorrect predictions for test data with only the first three providers:")
    analyze_predictions(y_test_first_three, y_pred_first_three, providers_test_first_three)

    # Test the model on test data with only the last provider
    X_test_last_one, y_test_last_one, providers_test_last_one = zip(*[(x, label, provider) for x, label, provider in zip(X_test, y_test, providers_test) if provider == 'others_dataset'])
    print('\n\n\n'+'='*20)
    print("Metrics for test data with only the last provider:")
    y_pred_last_one = clf.predict(X_test_last_one)
    calculate_metrics(y_test_last_one, y_pred_last_one)
    print("Incorrect predictions for test data with only the last provider:")
    analyze_predictions(y_test_last_one, y_pred_last_one, providers_test_last_one)

    return clf.score(X_test, y_test)





# def output_dataset_sizes(original_size, filtered_size, train_size, test_size, train_filtered_size, test_first_three_size, test_last_one_size):
#     print("Original dataset size:", original_size)
#     print("Filtered dataset size:", filtered_size)
#     print("Training dataset size:", train_size)
#     print("Test dataset size:", test_size)
#     print("Filtered training dataset size:", train_filtered_size)
#     print("Test dataset size with first three providers:", test_first_three_size)
#     print("Test dataset size with last provider:", test_last_one_size)

def calculate_dataset_sizes(dataset_path, filter_providers):
    import json
    from sklearn.model_selection import train_test_split

    dataset_file = open(dataset_path + "dataset.json", 'r')
    dataset = json.load(dataset_file)
    X = dataset['X']
    y = dataset['Y']
    providers = dataset['providers']  # Get the providers from the dataset
    original_size = len(X)
    # Filter training data for training
    filter_providers = ['packetstream', 'iproyal', 'honeygain', 'others_dataset']
    # 定义要过滤的提供者和每个提供者的最大数据量
    max_samples_per_label = 2000

    # 过滤数据
    filtered_X = []
    filtered_y = []
    filtered_providers = []  # 更新providers列表
    provider_label_counts = {provider: {0: 0, 1: 0} for provider in filter_providers}
    for feature, label, provider in zip(X, y, providers):
        if provider in ['packetstream', 'iproyal', 'honeygain']:
            if provider_label_counts[provider][label] < max_samples_per_label:
                filtered_X.append(feature)
                filtered_y.append(label)
                filtered_providers.append(provider)  # Update the providers list
                provider_label_counts[provider][label] += 1
        elif provider == 'others_dataset':
            filtered_X.append(feature)
            filtered_y.append(label)
            filtered_providers.append(provider)  # Add others_dataset provider without filtering
        else:
            filtered_X.append(feature)
            filtered_y.append(label)
            filtered_providers.append(provider)  # Update the providers list


    X = filtered_X
    y = filtered_y
    providers = filtered_providers
    filtered_size = len(filtered_X)
    # Split the data into training and test sets (80:20)
    X_train, X_test, y_train, y_test, providers_train, providers_test = train_test_split(X, y, providers, test_size=0.2, random_state=42)

    # Count the number of 0s and 1s in each part
    train_0s = y_train.count(0)
    train_1s = y_train.count(1)
    test_0s = y_test.count(0)
    test_1s = y_test.count(1)

    # Count the number of each provider in training and test sets with labels 0 and 1
    train_provider_counts = {provider: {0: 0, 1: 0} for provider in filter_providers}
    test_provider_counts = {provider: {0: 0, 1: 0} for provider in filter_providers}
    for provider, label in zip(providers_train, y_train):
        train_provider_counts[provider][label] += 1
    for provider, label in zip(providers_test, y_test):
        test_provider_counts[provider][label] += 1

    train_size = len(X_train)
    test_size = len(X_test)

    return {
        'original_size': original_size,
        'filtered_size': filtered_size,
        'train_size': train_size,
        'train_0s': train_0s,
        'train_1s': train_1s,
        'test_size': test_size,
        'test_0s': test_0s,
        'test_1s': test_1s,
        'train_provider_counts': train_provider_counts,
        'test_provider_counts': test_provider_counts
    }

# Overall performance: Train{A, B, C, Others} -> Test{A, B, C, Others} + Test{A}  + Test{B} + Test{C} + Test{Others} 
def train_and_evaluate(dataset_path, model_path):
    # Load the dataset
    with open(dataset_path + "dataset.json", 'r') as dataset_file:
        dataset = json.load(dataset_file)
    X = dataset['X']
    y = dataset['Y']
    providers = dataset['providers']

    # Filter data
    filter_providers = ['packetstream', 'iproyal', 'honeygain', 'others_dataset']
    max_samples_per_label = 20000
    filtered_X, filtered_y, filtered_providers = filter_data(X, y, providers, filter_providers, max_samples_per_label)

    # Split the data into training and test sets (80:20)
    X_train, X_test, y_train, y_test, providers_train, providers_test = train_test_split(filtered_X, filtered_y, filtered_providers, test_size=0.2, random_state=42)

    # Train the model on the training data
    clf = RandomForestClassifier(n_estimators=10)
    clf.fit(X_train, y_train)
    joblib.dump(clf, model_path + 'model.pkl')

    # Evaluate the model on the test data
    y_pred = clf.predict(X_test)
    print("Overall Test Metrics:")
    print(classification_report(y_test, y_pred,digits=4))

    # Evaluate the model on each provider
    for provider in set(providers_test):
        print(f"Metrics for Provider: {provider}")
        provider_X_test, provider_y_test = zip(*[(x, label) for x, label, prov in zip(X_test, y_test, providers_test) if prov == provider])
        provider_y_pred = clf.predict(provider_X_test)
        print(classification_report(provider_y_test, provider_y_pred,digits=4))

    # Output dataset sizes
    output_dataset_sizes(len(X), len(filtered_X), len(X_train), len(X_test), providers_train, y_train, providers_test, y_test, {prov: providers_test.count(prov) for prov in set(providers_test)})


def separate_data_by_providers(X, y, providers, train_providers, test_providers):
    train_X, train_y, train_providers_list = [], [], []
    test_X, test_y, test_providers_list = [], [], []

    for x, label, provider in zip(X, y, providers):
        if provider in train_providers:
            train_X.append(x)
            train_y.append(label)
            train_providers_list.append(provider)
        if provider in test_providers:  # 使用 if 而不是 elif
            test_X.append(x)
            test_y.append(label)
            test_providers_list.append(provider)

    return train_X, train_y, train_providers_list, test_X, test_y, test_providers_list

# 通用性实验 Train{A， Others} -> Test{A, B, C, Others} + Test{B} + Test{C} + Test{Others} 以及 Train{A/B， Others} -> Test{A, B, C, Others} + Test{C} + Test{Others} 
def train_and_evaluate2(dataset_path, model_path, train_providers):
    # 定义所有的提供商
    all_providers = ['packetstream', 'iproyal', 'honeygain', 'others_dataset']
    # 定义测试提供商
    test_providers = [provider for provider in all_providers if provider not in train_providers] + ['others_dataset']

    # 加载数据集
    with open(dataset_path + "dataset.json", 'r') as dataset_file:
        dataset = json.load(dataset_file)
    X = dataset['X']
    y = dataset['Y']
    providers = dataset['providers']

    # 过滤数据
    max_samples_per_label = 2000
    filtered_X, filtered_y, filtered_providers = filter_data(X, y, providers, train_providers + test_providers, max_samples_per_label)

    train_X, real_test_X,train_y, real_test_y,train_providers_list,_ = train_test_split(filtered_X, filtered_y, filtered_providers, test_size=0.2, random_state=42)



    # 根据 train_providers 和 test_providers 列表区分数据集
    train_X, train_y, train_providers_list, test_X, test_y, test_providers_list = separate_data_by_providers(filtered_X, filtered_y, filtered_providers, train_providers, test_providers)

    train_X, _,train_y, _,train_providers_list,_ = train_test_split(train_X, train_y, train_providers_list, test_size=0.2, random_state=42)

    _, test_X, _, test_y, _, test_providers_list = train_test_split(test_X, test_y, test_providers_list, test_size=0.2, random_state=42)

    # 训练模型
    clf = RandomForestClassifier(n_estimators=10)
    clf.fit(train_X, train_y)
    joblib.dump(clf, model_path + 'model.pkl')

    # 评估模型在整个测试集上的性能
    y_pred = clf.predict(real_test_X)
    print("Overall Test Metrics:")
    print(classification_report(real_test_y, y_pred, digits=4))

    # 分别评估模型在每个测试提供商上的性能
    # 分别评估模型在每个测试提供商上的性能
    for provider in test_providers:
        print(f"Metrics for Provider: {provider}")
        provider_data = [(x, label) for x, label, prov in zip(test_X, test_y, test_providers_list) if prov == provider]
        if provider_data:
            provider_X_test, provider_y_test = zip(*provider_data)
            provider_y_pred = clf.predict(provider_X_test)
            print(classification_report(provider_y_test, provider_y_pred, digits=4))
        else:
            print(f"No test samples available for provider: {provider}")


    # 输出数据集大小
    output_dataset_sizes(len(X), len(filtered_X), len(train_X), len(test_X), train_providers_list, train_y, test_providers_list, test_y, {prov: test_providers_list.count(prov) for prov in set(test_providers_list)})






def filter_and_limit_data(X, y, providers, train_providers, max_samples_per_provider):
    filtered_X, filtered_y, filtered_providers = [], [], []
    provider_label_counts = {provider: {0: 0, 1: 0} for provider in train_providers}
    for feature, label, provider in zip(X, y, providers):
        if provider in train_providers and provider_label_counts[provider][label] < max_samples_per_provider:
            filtered_X.append(feature)
            filtered_y.append(label)
            filtered_providers.append(provider)
            provider_label_counts[provider][label] += 1
    return filtered_X, filtered_y, filtered_providers





def filter_data(X, y, providers, filter_providers, max_samples_per_label):
    filtered_X, filtered_y, filtered_providers = [], [], []
    provider_label_counts = {provider: {0: 0, 1: 0} for provider in filter_providers}
    for feature, label, provider in zip(X, y, providers):
        if provider in filter_providers:
            if provider == 'others_dataset' or provider_label_counts[provider][label] < max_samples_per_label:
                filtered_X.append(feature)
                filtered_y.append(label)
                filtered_providers.append(provider)
                provider_label_counts[provider][label] += 1
    return filtered_X, filtered_y, filtered_providers



def filter_data2(X, y, providers, filter_providers, max_samples_per_label_train, max_samples_per_label_test):
    filtered_X, filtered_y, filtered_providers = [], [], []
    provider_label_counts_train = {provider: {0: 0, 1: 0} for provider in filter_providers}
    provider_label_counts_test = {provider: {0: 0, 1: 0} for provider in filter_providers}

    for feature, label, provider in zip(X, y, providers):
        if provider in filter_providers:
            if provider_label_counts_train[provider][label] < max_samples_per_label_train:
                filtered_X.append(feature)
                filtered_y.append(label)
                filtered_providers.append(provider)
                provider_label_counts_train[provider][label] += 1
            elif provider_label_counts_test[provider][label] < max_samples_per_label_test:
                filtered_X.append(feature)
                filtered_y.append(label)
                filtered_providers.append(provider)
                provider_label_counts_test[provider][label] += 1

    return filtered_X, filtered_y, filtered_providers



def output_dataset_sizes(original_size, filtered_size, train_size, test_size, train_providers, train_labels, test_providers, test_labels, test_provider_counts):
    print("Original dataset size:", original_size)
    print("Filtered dataset size:", filtered_size)
    print("Training dataset size:", train_size)
    print("Test dataset size:", test_size)

    # Count the number of 0s and 1s in the training dataset for each provider
    train_provider_label_counts = {prov: {0: 0, 1: 0} for prov in set(train_providers)}
    for provider, label in zip(train_providers, train_labels):
        train_provider_label_counts[provider][label] += 1
    print("Providers in Training dataset with label counts:", train_provider_label_counts)

    # Count the number of 0s and 1s in the test dataset for each provider
    test_provider_label_counts = {prov: {0: 0, 1: 0} for prov in set(test_providers)}
    for provider, label in zip(test_providers, test_labels):
        test_provider_label_counts[provider][label] += 1
    print("Providers in Test dataset with label counts:", test_provider_label_counts)

    print("Test dataset size for each provider:", test_provider_counts)

def output_dataset_sizes2(original_size, filtered_size, train_size, test_size, train_providers, test_providers, train_labels, test_labels):
    print("Original dataset size:", original_size)
    print("Filtered dataset size (used for training):", filtered_size)
    print("Training dataset size:", train_size)
    print("Test dataset size:", test_size)
    print("Providers used for training:", train_providers)
    print("Providers in the test dataset:", set(test_providers))

    # Count the number of 0s and 1s in the training dataset for each provider
    train_provider_label_counts = {prov: {0: 0, 1: 0} for prov in train_providers}
    for provider, label in zip(train_providers, train_labels):
        train_provider_label_counts[provider][label] += 1
    print("Label counts in Training dataset:", train_provider_label_counts)

    # Count the number of 0s and 1s in the test dataset for each provider
    test_provider_label_counts = {prov: {0: 0, 1: 0} for prov in set(test_providers)}
    for provider, label in zip(test_providers, test_labels):
        test_provider_label_counts[provider][label] += 1
    print("Label counts in Test dataset:", test_provider_label_counts)

def print_dataset_info(info):
    print("Original dataset size:", info['original_size'])
    print("Filtered dataset size:", info['filtered_size'])
    print("Training set size:", info['train_size'])
    print("  - Number of 0s:", info['train_0s'])
    print("  - Number of 1s:", info['train_1s'])
    print("  - Provider counts with labels 0 and 1:")
    for provider, counts in info['train_provider_counts'].items():
        print(f"    - {provider}: 0s={counts[0]}, 1s={counts[1]}")
    print("Testing set size:", info['test_size'])
    print("  - Number of 0s:", info['test_0s'])
    print("  - Number of 1s:", info['test_1s'])
    print("  - Provider counts with labels 0 and 1:")
    for provider, counts in info['test_provider_counts'].items():
        print(f"    - {provider}: 0s={counts[0]}, 1s={counts[1]}")




def calculate_metrics(actual, predicted):
    unique_classes = np.unique(actual)
    if len(unique_classes) == 1:
        class_names = [str(unique_classes[0])]
    else:
        class_names = ['other', 'relayed']

    

    if len(unique_classes) > 1:
        print(classification_report(actual, predicted, target_names=class_names, digits=10))
        tn, fp, fn, tp = confusion_matrix(actual, predicted).ravel()
        fpr = fp / (fp + tn)
        print("False Positive Rate: ", fpr)

        tpr = tp / (tp + fn)
        print("True Positive Rate (Recall): ", tpr)

        specificity = tn / (tn + fp)
        print("Specificity: ", specificity)

        fnr = fn / (fn + tp)
        print("False Negative Rate: ", fnr)

        accuracy = (tp + tn) / (tp + fp + fn + tn)
        print("Accuracy: ", accuracy)
    else:
        accuracy = accuracy_score(actual, predicted)
        print("Accuracy: ", accuracy)

def analyze_predictions(y_true, y_pred, providers):
    correct_predictions = {}
    incorrect_predictions = {}
    for true_label, pred_label, provider in zip(y_true, y_pred, providers):
        if true_label == pred_label:
            key = (provider, true_label)
            correct_predictions[key] = correct_predictions.get(key, 0) + 1
        else:
            key = (provider, true_label, pred_label)
            incorrect_predictions[key] = incorrect_predictions.get(key, 0) + 1

    print("Correct predictions:")
    for (provider, label), count in correct_predictions.items():
        print(f"Provider: {provider}, Label: {label}, Count: {count}")

    print("Incorrect predictions:")
    for (provider, true_label, pred_label), count in incorrect_predictions.items():
        print(f"Provider: {provider}, True label: {true_label}, Predicted label: {pred_label}, Count: {count}")

    print(f"Total correct predictions: {sum(correct_predictions.values())}")
    print(f"Total incorrect predictions: {sum(incorrect_predictions.values())}")


def get_pcap_files(folder_path, sample_size=10000):
    pcap_files = []
    labels = []

    # 定义一个递归函数来遍历所有子文件夹
    def traverse_folders(current_path, current_label):
        for entry in os.listdir(current_path):
            full_path = os.path.join(current_path, entry)
            if os.path.isdir(full_path):
                # 如果当前路径是一个文件夹，则递归遍历
                traverse_folders(full_path, current_label)
            elif entry.endswith('.pcap'):
                # 如果是 pcap 文件，则添加到列表中
                pcap_files.append(full_path)
                labels.append(current_label)

    # 遍历 "0" 和 "1" 文件夹
    for label in ['0', '1']:
        label_path = os.path.join(folder_path, label)
        if os.path.exists(label_path) and os.path.isdir(label_path):
            traverse_folders(label_path, int(label))

    # 随机采样 pcap 文件
    if len(pcap_files) > sample_size:
        sample_indices = random.sample(range(len(pcap_files)), sample_size)
        pcap_files = [pcap_files[i] for i in sample_indices]
        labels = [labels[i] for i in sample_indices]

    return pcap_files, labels


def predict_folder(folder_path, model_path = "./relayed_.pkl"):
    # 加载模型
    model = joblib.load(model_path)

    # 获取 pcap 文件和标签
    pcap_files, labels = get_pcap_files(folder_path)

    # 提取特征并进行预测
    valid_features = []
    valid_labels = []
    start_time = time.time()
    for filepath, label in zip(pcap_files, labels):
        features = get_feature_flow(filepath)
        if features != -1:
            valid_features.append(features)
            valid_labels.append(label)

    total_predictions = model.predict(valid_features)
    end_time = time.time()
    time_taken = end_time - start_time

    # 计算准确率
    accuracy = accuracy_score(valid_labels, total_predictions)

    # 打印结果
    print(f"Total files processed: {len(total_predictions)}")
    print(f"Time taken: {time_taken} seconds")
    print(f"Accuracy: {accuracy}")

    return total_predictions, time_taken, accuracy

def print_provider_counts(dataset_path):
    with open(dataset_path + "dataset.json", 'r') as dataset_file:
        dataset = json.load(dataset_file)
        providers = dataset['providers']
        labels = dataset['Y']

    # 初始化计数器
    provider_counts = {}
    for provider in set(providers):
        provider_counts[provider] = {'total': 0, 'label_0': 0, 'label_1': 0}

    # 计数
    for provider, label in zip(providers, labels):
        provider_counts[provider]['total'] += 1
        if label == 0:
            provider_counts[provider]['label_0'] += 1
        elif label == 1:
            provider_counts[provider]['label_1'] += 1

    # 打印结果
    for provider, counts in provider_counts.items():
        print(f"Provider: {provider}, Total: {counts['total']}, Label 0: {counts['label_0']}, Label 1: {counts['label_1']}")

def predict_folder(folder_path, model_path = "./model.pkl"):
    # 加载模型
    model = joblib.load(model_path)

    # 获取 pcap 文件和标签
    pcap_files, labels = get_pcap_files(folder_path)

    # 提取特征并进行预测
    valid_features = []
    valid_labels = []
    start_time = time.time()
    for filepath, label in zip(pcap_files, labels):
        features = get_feature_flow(filepath)
        if features != -1:
            valid_features.append(features)
            valid_labels.append(label)

    total_predictions = model.predict(valid_features)
    end_time = time.time()
    time_taken = end_time - start_time

    # 计算准确率
    accuracy = accuracy_score(valid_labels, total_predictions)

    # 打印结果
    print(f"Total files processed: {len(total_predictions)}")
    print(f"Time taken: {time_taken} seconds")
    print(f"Accuracy: {accuracy}")

    return total_predictions, time_taken, accuracy

def main():
    generation(sys.argv[1],dataset_path)
    train_and_evaluate(dataset_path,model_path)




if __name__=='__main__':
    main()
