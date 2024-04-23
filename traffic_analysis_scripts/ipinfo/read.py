import json


def get_json1():
    result_file = open('result.json','r')

    ip_country_org={}

    for line in result_file.readlines():
        line=line.strip()
        data=json.loads(line)

        ip=data['ip']
        country=data['country']

        if ip not in ip_country_org:
            ip_country_org[ip]=country
        else:
            continue

    ip_country_file=open('ip_country.json','w')
    json.dump(ip_country_org,ip_country_file)
    ip_country_file.close()

def get_json2():
    
    ip_country_file=open('ip_country.json','r')
    ip_country_org=json.load(ip_country_file)
    ip_country_file.close()



    packetstream_probe_number=0
    iproyal_probe_number=0
    total_probe_number=0
    packetstream_ip_number=0
    iproyal_ip_number=0
    total_ip_number=0

    input_json=open('./stat.json','r')
    input_stat=json.load(input_json)
    dict_x=input_stat['dict_x']
    dict_y=input_stat['dict_y']
    input_json.close()

    input_json=open('./stat2.json','r')
    input_stat=json.load(input_json)

    total=input_stat['total']
    total_dict_=input_stat['dict_']
    input_json.close()




    for key,value in dict_x.items():
        packetstream_probe_number+=value
    for key,value in dict_y.items():
        iproyal_probe_number+=value
    total_probe_number=packetstream_probe_number+iproyal_probe_number

    packetstream_ip_number=len(dict_x)
    iproyal_ip_number=len(dict_y)
    total_ip_number=len(total_dict_)

    query_packetstream_num=0
    query_iproyal_num=0
    query_total_num=len(ip_country_org)

    total_country_ip_count={}
    packetstream_country_ip_count={}
    iproyal_country_ip_count={}
    for ip,country in ip_country_org.items():
        if ip in dict_x:
            query_packetstream_num+=1
            if country not in packetstream_country_ip_count:
                packetstream_country_ip_count[country]=1
            else:
                packetstream_country_ip_count[country]+=1
        if ip in dict_y:
            query_iproyal_num+=1
            if country not in iproyal_country_ip_count:
                iproyal_country_ip_count[country]=1
            else:
                iproyal_country_ip_count[country]+=1
        if country not in total_country_ip_count:
            total_country_ip_count[country]=1
        else:
            total_country_ip_count[country]+=1

    print('packetstream ip 数量:',packetstream_ip_number,'查询ip数量:',query_packetstream_num,'占比:',round(query_packetstream_num*100/packetstream_ip_number,2),'%')
    print('iproyal ip 数量:',iproyal_ip_number,'查询ip数量:',query_iproyal_num,'占比:',round(query_iproyal_num*100/iproyal_ip_number,2),'%')
    print('所有 ip 数量:',total_ip_number,'查询ip数量:',query_total_num,'占比:',round(query_total_num*100/total_ip_number,2),'%')

    country_ip_count_json_file=open('country_ip_count.json','w')


    output_stat={}
    output_stat['packetstream_ip_number']=packetstream_ip_number
    output_stat['query_packetstream_num']=query_packetstream_num
    output_stat['iproyal_ip_number']=iproyal_ip_number
    output_stat['query_iproyal_num']=query_iproyal_num
    output_stat['total_ip_number']=total_ip_number
    output_stat['query_total_num']=query_total_num
    output_stat['packetstream_country_ip_count']=packetstream_country_ip_count
    output_stat['iproyal_country_ip_count']=iproyal_country_ip_count
    output_stat['total_country_ip_count']=total_country_ip_count
    json.dump(output_stat,country_ip_count_json_file)


def main():
    input_json=open("country_ip_count.json",'r')
    input_stat=json.load(input_json)
    packetstream_ip_number=input_stat['packetstream_ip_number']
    query_packetstream_num=input_stat['query_packetstream_num']
    iproyal_ip_number=input_stat['iproyal_ip_number']
    query_iproyal_num=input_stat['query_iproyal_num']
    total_ip_number=input_stat['total_ip_number']
    query_total_num=input_stat['query_total_num']
    packetstream_country_ip_count=input_stat['packetstream_country_ip_count']
    iproyal_country_ip_count=input_stat['iproyal_country_ip_count']
    total_country_ip_count=input_stat['total_country_ip_count']

    total_country_ip_count['CN'] += total_country_ip_count['TW']
    total_country_ip_count['TW'] = total_country_ip_count['CN']
    total_country_ip_count['TW']=0

    # total_country_ip_count['IN'] += total_country_ip_count['US']
    # total_country_ip_count['US'] = total_country_ip_count['IN']
    # total_country_ip_count['IN']=0

    list_1 = list(total_country_ip_count.items())
    total_country_ip_count_sort= dict(sorted(list_1,key = lambda x:x[1],reverse= True))

    i=0
    add_sum=0
    for country,ip_count in total_country_ip_count_sort.items():
        i+=1
        if i<=10:
            add_sum+=ip_count
            print(country,ip_count,round(ip_count*100/query_total_num,2))
    print(round(add_sum*100/query_total_num,2))

    print(len(packetstream_country_ip_count),len(iproyal_country_ip_count),len(total_country_ip_count))

if __name__ == "__main__":
    main()
