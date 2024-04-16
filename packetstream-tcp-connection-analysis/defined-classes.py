#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Dec 29 13:50:05 2021

@author: dongfangzhao

Classes. 
"""
import json

class Packet:
    def __init__(self):
        self.timestamp = None
        self.is_tcp = False
        self.is_udp = False
        self.is_dns = False
        self.is_outgoing = False ###
        self.src_ip = None
        self.src_port = None
        self.dst_ip = None
        self.dst_port = None
        self.is_first_tcp = False # whether it is the first packet of a new tcp connection
        self.raw_json = None
        self.is_dns_query = False
        self.tcp_seq = None
        self.tcp_ack = None

class CapFile:
    def __init__(self, src_file):
        self.src_file = src_file
        self.src_fd = open(src_file, 'r', encoding='utf8', errors='ignore')
        
    def next_packet(self):
        while True:
            is_end = False
            index = 0
            buffer = []
            while True:
                new_line = self.src_fd.readline().strip('\n')
                index += 1 
                ## either the starting [, or ,
                # either the starting [ or "  {\n"
                # if index == 1:
                #     continue
                if new_line == "[" or new_line == "]":
                    continue
                #if new_line == "\n":
                if new_line == "  },":
                    break
                elif not new_line: #new_line == "":
                    is_end = True
                    break
                buffer.append(new_line.strip())

            if is_end:
                return None
            buffer.append("}") ##
            packet_json = json.loads("".join(buffer))

            #print(type(packet_json))
            #print("this json is:", packet_json)###
            layers = packet_json['_source']['layers']
            is_tcp = 'tcp' in layers
            is_udp = 'udp' in layers
            is_ipv6 = 'ipv6' in layers
            if (not is_tcp) and (not is_udp): # ignore ICMP, or others
                continue
            if is_ipv6: # ignore ipv6
                continue
            if 'bootp' in layers: # intial packets when starting the emulator
                continue
            packet = Packet()
            packet.raw_json = packet_json
            packet.is_tcp = is_tcp
            packet.is_udp = is_udp
            packet.is_dns = 'dns' in layers
            packet.is_outgoing = layers['ip']['ip.src_host'] == '10.30.2.45' # local ip. 1h traffic
            #packet.is_outgoing = layers['ip']['ip.src_host'] == '10.30.2.47' # local ip. 1d traffic
            packet.src_ip = layers['ip']['ip.src_host']
            packet.dst_ip = layers['ip']['ip.dst_host']
            packet.src_port = layers['tcp']['tcp.srcport'] if is_tcp else layers['udp']['udp.srcport']
            packet.dst_port = layers['tcp']['tcp.dstport'] if is_tcp else layers['udp']['udp.dstport']
            packet.timestamp = float(layers['frame']['frame.time_epoch'])
            if packet.is_tcp and int(layers['tcp']['tcp.seq']) == 0:
                packet.is_first_tcp = True
            if packet.is_tcp:
                packet.tcp_seq = int(layers['tcp']['tcp.seq'])
                packet.tcp_ack = int(layers['tcp']['tcp.ack'])

            return packet
    def close(self):
        self.src_fd.close()
class Connection:
    def __init__(self):
        # no need for src ip, it is the same
        self.src_port = None
        self.dst_port = None
        self.dst_ip = None
        self.start_timestamp = None
        self.end_timestamp = None
        self.packet_count = 0
        self.tcp_seq = None
        self.tcp_ack = None
