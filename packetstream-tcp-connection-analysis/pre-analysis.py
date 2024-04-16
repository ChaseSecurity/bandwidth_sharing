#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Dec 29 13:54:07 2021

@author: dongfangzhao

Preliminary analysis.

input traffic file: src_traffic_file
"""

# setup
#%load_ext autoreload
#%autoreload 2
import logging
import os, sys
import json
from collections import defaultdict
import pandas as pd

from defined_classes import CapFile, Connection, Packet
import pickle

result_dir = 'logging'
if not os.path.exists(result_dir):
    os.makedirs(result_dir)
format_str = '%(asctime)s %(levelname)s %(message)s'
formatter = logging.Formatter(fmt=format_str)
logging_file = os.path.join(
    result_dir,
    'log.log'
)
file_handler = logging.FileHandler(filename=logging_file)
file_handler.setFormatter(formatter)
file_handler.setLevel(logging.INFO)
std_handler = logging.StreamHandler(stream=sys.stdout)
std_handler.setFormatter(formatter)
std_handler.setLevel(logging.INFO)
root_logger = logging.getLogger('')
root_logger.handlers = []
root_logger.setLevel(logging.INFO)
root_logger.addHandler(std_handler)
root_logger.addHandler(file_handler)
logging.info('started')

domains = {'api.packetstream.io', 'packetstream.io', 'proxy.packetstream.io'}

src_traffic_file = '../../packetstream-1h-proxy-on-no-promiscuous.json'
logging.info("src ip is defined in class CapFile")
logging.info("File \"%s\" is under process",src_traffic_file)
#%%
'''
Get proxy server ip and save those ips to pickle file.
Note: 1d or 1h file 
'''
proxy_server_ips = set()
server_ip_connections = {}
cap_file = CapFile(src_traffic_file)
count = 0
while True:
    packet = cap_file.next_packet()
    if not packet:
        break
    count+=1
    #print(count, "packet")
    # print(count, end = "\r")
    # if count == 1505:
    #     print("let's see what's happening here.")
    #     print(packet.raw_json)
    #     continue
    if not packet.is_dns:
        continue
    if "Answers" in packet.raw_json["_source"]["layers"]["dns"]:
        dns_answers_dict = packet.raw_json["_source"]["layers"]["dns"]["Answers"]
        for key in dns_answers_dict.keys():
            #print(key)
            if "type A" in key and "packetstream" in key:
                #proxy_server_ips.add(dns_answers_dict[key]["dns.a"])
                #print(dns_answers_dict[key])
                this_domain = dns_answers_dict[key]["dns.resp.name"]
                this_ip = dns_answers_dict[key]["dns.a"]
                if this_domain in domains:
                    proxy_server_ips.add(this_ip)
                # if this_domain not in server_ip_connections:
                #     server_ip_connections[this_domain] = set(this_ip)
                # else:
                #     server_ip_connections[this_domain].add(this_ip)
#print(server_ip_connections)
print(proxy_server_ips)
print(count, " packets")
pickle_file = "1h_proxy_server_ips.p"
pickle.dump(proxy_server_ips, open(pickle_file, "wb" ) )
#%%
logging.info('pickle dump to %s', pickle_file)
#%%
'''
Load proxy server ips from corresponding pickle file.
Note: 1d or 1h file.
'''
proxy_server_ips = pickle.load( open("1h_proxy_server_ips.p", "rb" ) )
logging.info('pickle file %s loaded', "1h_proxy_server_ips.p")
#%%
logging.info('proxy server ips loaded')
#%%
"""
# count all connections, and identify proxy connections
# only consider tcp here
check if the five tuple is unique.
"""

cap_file = CapFile(src_traffic_file)
unique_dst_ips = defaultdict(int)
unique_dst_ports = defaultdict(int)
#connection_tuple_to_latest_identifier = {} 
connection_tuple_to_latest_identifier = defaultdict(str)
unique_connections = {}
print_count = 0
# the same connection tuple(src_port, dest_ip_port) 
# can be reused by a new connection, therefore, we need to record latest connection 
# to update its end_timestamp
connection_tuple_to_latest_identifier = {}
packet_count = 0
connection_count = 0
proxy_tcp_connection_count = 0
keyerror_count = 0
five_tuple_set = set()
store = []
print('Analyzing ', src_traffic_file)
while True:
    packet = cap_file.next_packet()
    if packet is None:
        break
    if not packet.is_tcp:
        continue
    if not packet.is_outgoing: # outgoing packet from local ip. 
        continue
    packet_count += 1
    if packet_count % 10000 == 0:
        logging.info(
            "got %d tcp packets, %d connections",
            packet_count,
            len(unique_connections),
        )
    connection_tuple = "{src_port}_{dst_ip}_{dst_port}".format(
        src_port=packet.src_port,
        dst_ip=packet.dst_ip,
        dst_port=packet.dst_port,
    )
    identifier = "{src_port}_{dst_ip}_{dst_port}_{timestamp}".format(
        src_port=packet.src_port,
        dst_ip=packet.dst_ip,
        dst_port=packet.dst_port,
        timestamp=str(packet.timestamp),
    )
    if packet.is_first_tcp: # tcp seq 0
        connection_count += 1
        connection = Connection()
        if packet.dst_ip in proxy_server_ips:
            proxy_tcp_connection_count += 1
            five_tuple_set.add(identifier)
            store.append(identifier)
        connection_tuple_to_latest_identifier[connection_tuple] = identifier
        unique_connections[identifier] = connection
        connection.src_port = packet.src_port
        connection.dst_port = packet.dst_port
        connection.dst_ip = packet.dst_ip
        connection.start_timestamp = packet.timestamp
        connection.end_timestamp = packet.timestamp
        connection.packet_count = 1
        connection.tcp_seq = packet.tcp_seq
        connection.tcp_ack = packet.tcp_ack

cap_file.close()
# logging.info(
#     "Overall, got %d tcp packets, %d connections. %d keyerrors",
#     packet_count,
#     len(unique_connections),
#     keyerror_count
# )
logging.info(
    "Overall, got %d outgoing tcp packets, %d tcp connections, %d proxy tcp connections, %d unique proxy tcp connections",
    packet_count,
    connection_count,
    proxy_tcp_connection_count,
    len(five_tuple_set)
)














