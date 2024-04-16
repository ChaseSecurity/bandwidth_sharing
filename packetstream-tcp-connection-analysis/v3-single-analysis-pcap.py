#%%
from multiprocessing.connection import answer_challenge
import re
import subprocess
import os,sys
from random import choice
from os import listdir
from os.path import join, isfile
from threading import local
# from tkinter.tix import Tree
# from treelib import Tree,Node
import tldextract
import logging
from collections import defaultdict
import pandas as pd
import pickle
from defined_classes import CapFile, Connection, Packet
import pprint
import json
import time
from ipwhois import IPWhois
"""
domain_ips_mappings
not consider domain-cname chains.

Usage: python3 v3-single-analysis-pcap.py iproyal-asp-09-07/traffic/iproyal_aspServer_2022-06-19_03-05-15.pcap (local_host)
"""
#%%
# Functions definitions
def check_sys_argv():
    if len(sys.argv) < 2:
        sys.exit('Error usage.\nRUN: python3 v3-single-analysis-pcap.py xx.pcap (local_host)')
def get_localhost(choice, hosts_dict):
    if choice in hosts_dict:
        local_host = hosts_dict[choice]
    else:
        # asp/boa, packetstream 172.19.0.2, honeygain 172.19.0.3, iproyal 172.19.0.4, nanowire 172.19.0.5
        if 'packetstream' in choice:
            local_host = '172.19.0.2'
        elif 'honeygain' in choice:
            local_host = '172.19.0.3'
        elif 'iproyal' in choice:
            local_host = '172.19.0.4'
        elif 'nanowire' in choice:
            local_host = '172.19.0.5'
        elif len(sys.argv) == 3:
            local_host = sys.argv[2] # if argv2 is none?
        else:
            sys.exit('No local host found\nTRY RUN: python3 v3-single-analysis-pcap.py xx.pcap <local_host>')
    return local_host
# dns related handlers
def get_domain_ips_mappings(src_traffic_file, local_host):
    count = 0
    domain_ips_mappings = defaultdict(set)
    cap_file = CapFile(src_traffic_file, local_host)
    while True:
        packet = cap_file.next_packet()
        if not packet:
            break
        count+=1
        if count % 10000 == 0:
            print(f'processed {count} packages.')
        if not packet.is_dns:
            continue
        if "Answers" in packet.raw_json["_source"]["layers"]["dns"] and "Queries" in packet.raw_json["_source"]["layers"]["dns"]:
            queries= packet.raw_json["_source"]["layers"]["dns"]["Queries"].keys()
            answer_chains_dict_set = defaultdict(set) # queried_domain: {queried_domain, cnames}
            for query in queries:
                if 'type A,' in query: # ignore IPv6 type AAAA,
                    queried_domain = query.split(':')[0]
                    answer_chains_dict_set[queried_domain].add(queried_domain)
            for answer in packet.raw_json["_source"]["layers"]["dns"]["Answers"].keys():
                if 'type CNAME,' in answer or 'type A,' in answer:
                    answer_uri = answer.split(':')[0]
                    if 'type CNAME,' in answer:
                        cname = answer.split('cname ')[1] # cname
                        parent = answer_uri
                        add_cname2ancestor_domain(cname, parent, answer_chains_dict_set)
                    if 'type A,' in answer:
                        ip = answer.split('addr ')[1]
                        parent = answer_uri
                        associated_domain = get_associated_domain_from_answer_chain_set(parent, answer_chains_dict_set)
                        add_ip2domain_ips_mappings(ip, associated_domain, domain_ips_mappings)
                        
    return domain_ips_mappings
def get_ip_domains_mapping(domain_ips_mappings):
    ip_domains_mappings = defaultdict(set)
    for domain in domain_ips_mappings:
        for ip in domain_ips_mappings[domain]:
            ip_domains_mappings[ip].add(domain)
    return ip_domains_mappings
def add_cname2ancestor_domain(cname, parent, answer_chains_dict_set):
    for queried_domain in answer_chains_dict_set:
        if parent in answer_chains_dict_set[queried_domain]:
            if cname not in answer_chains_dict_set[queried_domain]:
                answer_chains_dict_set[queried_domain].add(cname)
def get_associated_domain_from_answer_chain_set(parent, answer_chains_dict_set):
    for queried_domain in answer_chains_dict_set:
        if parent in answer_chains_dict_set[queried_domain]:
            return queried_domain
def add_ip2domain_ips_mappings(ip, associated_domain, domain_ips_mappings):
    if ip not in domain_ips_mappings[associated_domain]:
        domain_ips_mappings[associated_domain].add(ip)

## dns related handlers END
######
def get_proxy_server_ips(provider, domain_ips_mappings):
    proxy_server_ips = set()
    for domain in domain_ips_mappings:
        if provider in domain:
            for ip in domain_ips_mappings[domain]:
                proxy_server_ips.add(ip)
    return proxy_server_ips
def get_provider(choice):
    return choice.split('-')[0]
def get_proxy_server_uris(provider, domain_ips_mappings):
    proxy_server_uris = set()
    for domain in domain_ips_mappings:
        if provider in domain:
            proxy_server_uris.add(domain)
    return proxy_server_uris

#%%
#sys.argv = ['v3-single-analysis-pcap.py', 'iproyal-asp-09-07/traffic/iproyal_aspServer_2022-06-19_03-05-15.pcap']
#%%
print(f'!!!!!!!!!\n\
        current sys.argv is preset as:  {sys.argv}\n\
        !!!!!!!!!')


#%%
"""
check run command and get target file, localhost
"""
# datapath = '/Volumes/ExtremeSSD/EtDATA/'
datapath = '/Volumes/Seagate/bandwidth-sharing/asp/'
check_sys_argv()
choice = sys.argv[1]
src_traffic_file = join(datapath, choice)
print(f'src_traffic_file: {src_traffic_file} \n')
hosts_dict = {
            "honeygain-mbp-2-22-10pm.pcap": '192.168.1.11',
            "honeygain-mbp-2-23-0020am.pcap": '192.168.1.11',
            "iproyal-mbp-2-25-0229am.pcap": "192.168.1.11",
            "iproyal-mbp-2-22-0251am.pcap": "'192.168.1.11'",
            "packetstream-aws-1.pcap": "172.17.0.2",
            "packetstream-mbp-2.pcapng": "10.30.2.47",
            "packetstream-vmdocker-2.pcap": '172.17.0.2',
            "packetstream-vmdocker-4.cap": '172.17.0.2',
            "packetstream-mbp-1.pcapng": "10.30.2.45",
            "honeygain-mbp-icloudoff-03060045.pcapng": '192.168.1.11',
            "icloudOffAllOff-30min.pcapng": "192.168.1.11",
            "packetstream-proxy-off-no-promiscuous-1h.pcapng": "10.30.2.45",
            "honeygain-ubuntu-03211150pm.pcap": "172.17.0.2",
            "honeygain-ubuntu-03242249.pcap": "172.17.0.2", # docker ip is always starting from 172.17.0.2
            "packetstream-iuasp-03312214.pcap": "172.17.0.3",
            "honeygain-iuasp-1651353898_04_30.pcap": "172.19.0.3",
            "iproyal-iuasp-1651353293_04_30.pcap": "172.19.0.4",
            "nanowire-iuasp-1651378198_05_01.pcap": "172.19.0.5",
            "packetstream-iuasp-1651350211_04_30.pcap": "172.19.0.2",
            "packetstream_iuserver_183815_05_07.pcap": "172.19.0.2",
            "honeygain_iuserver_222133_05_07.pcap": "172.19.0.3",
            "iproyal_iuserver_224718_05_07.pcap": "172.19.0.4",
            "nanowire_iuserver_225745_05_07.pcap": "172.19.0.5"
            }
local_host = get_localhost(choice, hosts_dict)

print(f'src_traffic_file: {src_traffic_file} \nlocal host: {local_host}')
#%%
traffic_json = ''.join(src_traffic_file.split('.')[:-1])+'.json'
if not os.path.exists(traffic_json):
    print(f'!!!! json file NOT FOUND:\n {traffic_json}\n\
    tshark converting...')
    # os.system(f'tshark -r {src_traffic_file} -T json > {traffic_json}')
    os.system(f'tshark -r {src_traffic_file} -T json > {traffic_json}')
    print(f'json traffic file generated. Good to proceed\n {traffic_json}')
    time.sleep(4)
else:
    print(f'Good to Proceed json Analysis. \n{traffic_json}')
# src_traffic_file = traffic_json
#%%
# domain_ips_mappings = defaultdict(set)
domain_ips_mappings = get_domain_ips_mappings(traffic_json, local_host) # defaultdict(set)

#%%
# pprint.pprint(domain_ips_mappings)
## is it possible that proxy provider name is in cname???

#%%

ip_domains_mappings = get_ip_domains_mapping(domain_ips_mappings)
#%%
# pprint.pprint(ip_domains_mappings)

#%%

def generate_tshark_statistics_txt(datapath, choice):
    """
    Generating tcp_statistics_csv based on tshark statistics file(txt). 
    """
    tshark_tcp_statistics = join(datapath, choice.split('.')[0]+'.txt')
    if (not os.path.exists(tshark_tcp_statistics)):
        # print('!!!!! Please run tshark command line to generate statistics file(txt)\n \
        # tshark -r src_traffic_file -q -z \'conv,tcp\' > tcp_statistics_txt')
        print(f'!!!! tshark tcp statistics NOT FOUND. Generating statistics file......')
        os.system(f'tshark -r {src_traffic_file} -q -z "conv,tcp" > {tshark_tcp_statistics}')
        print('tshark tcp statistics generated. Good to proceed.')
        time.sleep(4)
    else:
        print(f'Good to Proceed. \n tshark tcp statistics txt exists:{tshark_tcp_statistics}')
    return tshark_tcp_statistics
#%%
# tshark_tcp_statistics = generate_tshark_statistics_txt(datapath, choice)

#%%
def get_tcp_statistics_csv(datapath, choice):
    """
    Prerequisite: tshark get tcp statistics txt.
    TCP connection statistics starting from the 6th line.split():
        Address A:Port A,<->,Address B:Port B,Frames(<-),Bytes(<-),Frames(->),Bytes(->),Frames(Total),Bytes(Total),RelativeStart,Duration
    Convert to:
        Address A,Port A,Address B,Port B,Frames(<-),Bytes(<-),Frames(->),Bytes(->),Frames(Total),Bytes(Total),RelativeStart,Duration(s)
    """
    tshark_tcp_statistics = generate_tshark_statistics_txt(datapath, choice)
    tcp_statistics_csv = join(datapath, choice.split('.')[0]+'.csv')
    if (not os.path.exists(tcp_statistics_csv)):
        skip_line = 0
        line_num = 0
        to_write = open(tcp_statistics_csv, 'w+')
        header = 'Address A,Port A,Address B,Port B,Frames(<-),Bytes(<-),Frames(->),Bytes(->),Frames(Total),Bytes(Total),RelativeStart,Duration(s)'
        with open(tshark_tcp_statistics,'r') as f:
            for line in f:
                if skip_line < 5: # skip first 5 lines
                    skip_line += 1
                    if skip_line == 5:
                        # write header
                        to_write.write(header+'\n')
                    continue
                if '==========================' in line:
                    break
                splited = line.split()
                addr_a = splited[0].split(':')[0]
                port_a = splited[0].split(':')[1]
                addr_b = splited[2].split(':')[0]
                port_b = splited[2].split(':')[1]
                addresses = [addr_a,port_a,addr_b,port_b]
                other_metrics = splited[3:]
                metrics = ','.join(addresses+other_metrics)
                #print(line.split())
                to_write.write(metrics+'\n')
        to_write.close()        
        print(f'TCP connection statistics CSV completed: {tcp_statistics_csv}')
    else:
        print(f'Good to Proceed. \n tcp statistics csv exists:{tcp_statistics_csv}')
    return tcp_statistics_csv
#%%
tcp_statistics_csv = get_tcp_statistics_csv(datapath, choice)

#%%

provider = get_provider(choice)
proxy_server_ips = get_proxy_server_ips(provider, domain_ips_mappings)
proxy_server_uris = get_proxy_server_uris(provider, domain_ips_mappings)

#%%
metrics = {
    'Pcap File': choice,
    'Provider': '',
    'Platform': '',
    'Duration': '',
    'Local Host': '',
    'Proxy Server URIs': set(), # Provider URI. e.g. api.packetstream.io
    'Proxy Server IP Number': 0,
    'Total Tcp Connection Number': 0,
    'Proxy Tcp Connection Number': 0,
    'Proxy Tcp Connection Number Percent': 0,
    'Total Tcp Connection Size': 0, # Mb: Bytes/1000000
    'Proxy Tcp Connection Size Percent': 0,
    'Proxy Tcp Connection Size': 0,
    'unresolved_ip_number': 0,
    'resolved_ip_number': 0,
    'unresolved_ip_connection_size': 0,
    'resolved_ip_connection_size': 0,
    'unresolved_resolved_ip_connection_size_ratio': '', # a:b
    'Local-Domain Tcp Connections': defaultdict(lambda: [0,0]), # {dom1: [Bytes, Percentage outOf total traffic], dom2: [Bytes, Percentage outOf total traffic], ...}
    'unresolved_ips': set(),
    'Local-IP Tcp Connections': defaultdict(lambda: [0,0,[]]), # [ip, percentage traffic, [domain1, domain2]]
    'IP-Domain': defaultdict(set), # {ip: {domain1,domain2}}
    'Domain-IP': defaultdict(set),
    'Proxy Server IPs': set()
    # 'Non Proxy IP-Domain': defaultdict(set), # {ip: {domain1,domain2}}
    # 'Non Proxy Domain-IP': defaultdict(set)
}

#%%


#%%
# calculate metrics from statistics csv and previous results
df = pd.read_csv(tcp_statistics_csv)

proxy_tcp_connection_size = 0
proxy_tcp_connection_number = 0
total_tcp_connection_number = df.shape[0]
total_tcp_connection_size = 0

local_domain_tcp_connections = defaultdict(lambda: [0,0]) # {dom1: [Bytes, Percentage outOf total traffic]
local_ip_tcp_connections = defaultdict(lambda: [0,0,[]]) # [ip, percentage traffic, [domain1, domain2]]




#%%
# pickle.dump(ip_domains_mappings, open('ip_domains_mappings.p', 'wb'))
# pickle.dump(domain_ips_mappings, open('domain_ips_mappings.p', 'wb'))



#%%

for i in range(len(df)):
    # local host is always put in address A by tshark.
    if df.iloc[i]['Address A'] == local_host:
        
        local_ip_tcp_connections[df.iloc[i]['Address B']][0] += df.iloc[i]['Bytes(Total)']
        # metrics['Local-IP Tcp Connections'][df.iloc[i]['Address B']][1] += 1
        mapped_domains = ip_domains_mappings[df.iloc[i]['Address B']]
        domain_num = len(mapped_domains)
        for domain in mapped_domains:
            local_domain_tcp_connections[domain][0] += (df.iloc[i]['Bytes(Total)'] / domain_num)
            #metrics['Local-Domain Tcp Connections'][domain][1] += 1
        if df.iloc[i]['Address B'] in proxy_server_ips:
            proxy_tcp_connection_size += df.iloc[i]['Bytes(Total)']
            proxy_tcp_connection_number += 1
#%%
resolved_ip_connection_size = 0
resolved_ip_number = 0
unresolved_ip_connection_size = 0
unresolved_ip_number = 0
unresolved_ips = set()
# print(len(ip_domains_mappings['8.42.17.166'])) #0
for i in range(len(df)):
    # local host is always put in address A by tshark.
    if df.iloc[i]['Address A'] == local_host:
        addressB = df.iloc[i]['Address B']
        if addressB == '8.8.8.8':
            continue
        if len(ip_domains_mappings[addressB]) == 0: # unresolved
            unresolved_ip_number += 1
            unresolved_ip_connection_size += df.iloc[i]['Bytes(Total)']
            unresolved_ips.add(addressB)
        else:
            resolved_ip_number += 1
            resolved_ip_connection_size += df.iloc[i]['Bytes(Total)']
#%%
print(unresolved_ip_number, resolved_ip_number)
print('unresolved ips:\n', unresolved_ips)
#%%
unresolved_ip_connection_size_ratio = unresolved_ip_connection_size/(unresolved_ip_connection_size+resolved_ip_connection_size)
resolved_ip_connection_size_ratio = resolved_ip_connection_size/(unresolved_ip_connection_size+resolved_ip_connection_size)
unresolved_resolved_ip_connection_size_ratio = f'{unresolved_ip_connection_size_ratio}:{resolved_ip_connection_size_ratio}'
# print(f'resolved_ip_connection_size_ratio:{resolved_ip_connection_size_ratio}')

# print(f'unresolved_ip_connection_size_ratio: {unresolved_ip_connection_size_ratio}')


#%%
total_tcp_connection_size = df['Bytes(Total)'].sum()
#%%
metrics['Pcap File'] = choice
metrics['Provider'] = choice.split('-')[0]
metrics['Platform'] = choice.split('-')[1]
metrics['Local Host'] = local_host
metrics['Proxy Server URIs'] = proxy_server_uris
metrics['Proxy Server IPs'] = proxy_server_ips
metrics['Proxy Server IP Number'] = len(proxy_server_ips)
metrics['unresolved_ip_number'] =  unresolved_ip_number
metrics['resolved_ip_number'] = resolved_ip_number
metrics['resolved_ip_connection_size'] = resolved_ip_connection_size
metrics['unresolved_ip_connection_size'] = unresolved_ip_connection_size
metrics['unresolved_resolved_ip_connection_size_ratio'] = unresolved_resolved_ip_connection_size_ratio # a:b
metrics['Total Tcp Connection Size'] = total_tcp_connection_size
metrics['Proxy Tcp Connection Size'] = proxy_tcp_connection_size
metrics['Proxy Tcp Connection Number'] = proxy_tcp_connection_number
metrics['Total Tcp Connection Number'] = total_tcp_connection_number
metrics['Local-Domain Tcp Connections'] = local_domain_tcp_connections
metrics['unresolved_ips'] = unresolved_ips
metrics['Local-IP Tcp Connections'] = local_ip_tcp_connections
metrics['IP-Domain'] = ip_domains_mappings
metrics["Domain-IP"] = domain_ips_mappings
#%%
# pprint.pprint(metrics)

#%%
metrics['Proxy Tcp Connection Size Percent'] = metrics['Proxy Tcp Connection Size']/metrics['Total Tcp Connection Size']
metrics['Proxy Tcp Connection Number Percent'] = metrics['Proxy Tcp Connection Number'] / metrics['Total Tcp Connection Number']




#%%
"""
1. Bytes to Mb: Bytes/1000000

2. And For metrics
    'Local-Domain Tcp Connections': defaultdict(lambda: [0,0]), # {dom1: [Bytes, Percentage outOf total traffic], dom2: [Bytes, Percentage outOf total traffic], ...}
    'Local-IP Tcp Connections': defaultdict(lambda: [0,0,'domainname']), 
        - Update Percentage outof total traffic
        - Update 'domainname'

"""
metrics['Total Tcp Connection Size'] /= 1000000
metrics['Proxy Tcp Connection Size'] /= 1000000
metrics['resolved_ip_connection_size'] /= 1000000
metrics['unresolved_ip_connection_size'] /= 1000000
for ip in metrics['Local-IP Tcp Connections']:
    metrics['Local-IP Tcp Connections'][ip][0] /= 1000000
    metrics['Local-IP Tcp Connections'][ip][1] = metrics['Local-IP Tcp Connections'][ip][0] / metrics['Total Tcp Connection Size']
    if len(metrics['IP-Domain'][ip]) > 0:
        metrics['Local-IP Tcp Connections'][ip][2] = list(metrics['IP-Domain'][ip])
    else:
        try:
            #metrics['Local-IP Tcp Connections'][ip][2].append('IPWhois:'+IPWhois(ip).lookup_whois()['nets'][0]['description'])
            # metrics['Local-IP Tcp Connections'][ip][2].append('IPWhois:'+IPWhois(ip).lookup_whois()['asn_description'])
            metrics['Local-IP Tcp Connections'][ip][2].append('IP lookup')
        except:
            metrics['Local-IP Tcp Connections'][ip][2].append('Private IP')

local_domain_tcp_total_percentage = 0
for domain in metrics['Local-Domain Tcp Connections']:
    metrics['Local-Domain Tcp Connections'][domain][0] /= 1000000
    metrics['Local-Domain Tcp Connections'][domain][1] = metrics['Local-Domain Tcp Connections'][domain][0] / metrics['Total Tcp Connection Size']
    local_domain_tcp_total_percentage += metrics['Local-Domain Tcp Connections'][domain][1]

print(f'local_domain_tcp_total_percentage: {local_domain_tcp_total_percentage}')




#%%
"""
sort mapping dict based on value(tcp connection size) in local-ip, local-domain tcp connections
"""
# x is the dict
# x = {k: v for k, v in sorted(x.items(), key=lambda item: item[1])}
def sort_dict(dic, sorting_key_item_indx):
    """
    sort mapping dict based on value(tcp connection size) in local-ip, local-domain tcp connections
    """
    # {k: v for k, v in sorted(metrics['Local-IP Tcp Connections'].items(), key=lambda item: item[1], reverse = True)}
    return {k: v for k, v in sorted(dic.items(), key=lambda item: item[sorting_key_item_indx], reverse = True)}


metrics['Local-IP Tcp Connections'] = {k: v for k, v in sorted(metrics['Local-IP Tcp Connections'].items(), key=lambda item: item[1], reverse = True)}
metrics['Local-Domain Tcp Connections'] = {k: v for k, v in sorted(metrics['Local-Domain Tcp Connections'].items(), key=lambda item: item[1], reverse = True)}
#%%

#%%
"""
Output metrics to report-xx.txt
"""
report_dir = join(datapath, 'report/')
if not os.path.exists(report_dir):
    os.makedirs(report_dir)

choice = choice.split('/')[-1]
report = join(report_dir, 'report-'+choice.split('.')[0]+'.txt')
print(report)

with open(report, 'w') as f:
    pprint.pprint(metrics, f, sort_dicts=False)

#%%

# print(metrics['Local-Domain Tcp Connections'])
# # %%
# print(ip_domains_mappings)
#%%
other = 3023.616368-1956.592297+19.467122
proxy_ps_io = 1956.592297
print(proxy_ps_io/(other+proxy_ps_io), other/(other+proxy_ps_io))
# %%


# unresolved2 = {'103.124.186.207',
#                     '103.124.186.209',
#                     '104.16.181.30',
#                     '104.18.41.98',
#                     '104.21.35.77',
#                     '104.22.33.225',
#                     '104.244.42.200',
#                     '108.156.245.52',
#                     '108.171.202.195',
#                     '135.148.103.134',
#                     '135.148.103.150',
#                     '142.250.185.142',
#                     '142.250.65.164',
#                     '157.240.229.37',
#                     '172.253.63.154',
#                     '18.165.98.14',
#                     '185.28.222.12',
#                     '23.217.13.17',
#                     '35.239.49.205',
#                     '52.223.40.198',
#                     '54.192.76.120',
#                     '54.192.76.125',
#                     '54.192.76.87',
#                     '8.26.41.246',
#                     '8.42.17.132',
#                     '8.42.17.141',
#                     '8.42.17.166',
#                     '8.42.17.167',
#                     '8.42.17.185',
#                     '81.31.201.139',
#                     '81.31.201.155',
#                     '81.31.201.156',
#                     '81.31.203.144',
#                     '81.31.203.186',
#                     '99.181.97.149'}
# unresolved1 = {'108.138.167.20', '199.232.210.131', '8.26.41.250', '52.223.241.21', '52.85.132.109', '8.26.41.246', '81.31.203.151', '172.217.168.194', '45.79.106.58', '103.124.186.200', '52.223.241.1', '103.124.186.207', '104.18.7.178', '23.212.181.205', '157.240.13.55', '185.28.223.11', '142.251.33.99', '8.26.41.251', '81.31.203.144', '142.250.65.196', '8.26.41.253', '146.75.28.157', '142.251.16.155', '103.124.186.210', '135.148.103.150', '151.101.0.84', '103.124.186.209', '81.31.201.136', '172.253.63.155', '35.190.43.134', '142.250.69.202', '208.83.242.82', '142.250.64.98', '99.84.66.101', '172.217.2.100', '104.18.6.178', '8.42.17.132', '74.119.118.154', '142.250.65.67', '142.250.186.174', '35.227.197.177', '51.81.155.182', '8.42.17.166', '172.217.14.229', '185.30.179.6', '188.114.99.171', '81.31.203.150', '52.223.241.20', '18.67.76.106', '208.95.112.1', '81.31.201.155', '185.28.222.11', '185.28.222.12', '142.250.80.99', '157.240.7.53', '47.107.26.232', '172.217.2.110'}
# print('repeated unresolved ips:')
# for ip1 in unresolved1:
#     if ip1 in unresolved2:
#         print(ip1)