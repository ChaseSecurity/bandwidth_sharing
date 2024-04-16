import json
import socket
import os
import csv
def is_dns_server(ip):
    try:
        socket.gethostbyaddr(ip)
        return True
    except socket.herror:
        return False
def is_single_digit_ip(ip_address):
    # Split the IP address into parts
    parts = ip_address.split(".")

    # If there aren't 4 parts, it's not a valid IP address
    if len(parts) != 4:
        return False

    for part in parts:
        # Check if part is a digit
        if not part.isdigit():
            return False

        # Convert string to number
        number = int(part)

        # Check if number is single digit
        if number < 0 or number > 9:
            return False

    # If we got through the loop without returning False, it means every part is a single digit
    return True
import csv
import json

import csv
def map_provider_to_docker_ip(string):
    ip_mapping = {
        'packetstream': '172.19.0.2',
        'honeygain': '172.19.0.3',
        'iproyal': '172.19.0.4'
    }
    # Get the corresponding IP from the dictionary, return None if the string is not found
    return ip_mapping.get(string, None)
def read_malicious_ip_stat_file(provider,stat_file_path, output_dir_path):
    with open(stat_file_path, 'r') as f:
        data = json.load(f)
    malicious_ips = {}
    for ip, values in data['remote_ip_server_ip_timestamps'].items():
        if is_single_digit_ip(ip):
            continue
        servers = set()
        for value in values:
            server_ip, timestamp = value
            if is_single_digit_ip(server_ip):
                continue
            if ip not in malicious_ips:
                malicious_ips[ip] = []
            malicious_ips[ip].append({'server_ip': server_ip, 'timestamp': timestamp})
    dir_path = output_dir_path
    csv_file_path = os.path.join(dir_path, f'malicious_ips_asp_{provider}_samples.csv')

    # Check if the directory exists, if not, create it
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)

    # Open the file in write mode
    with open(csv_file_path, 'w', newline='') as csvfile:
        fieldnames = ['proxy node ip', 'malicious ip', 'timestamp']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for ip, servers in malicious_ips.items():
            
            for server in servers:
                writer.writerow({'proxy node ip': map_provider_to_docker_ip(provider), 'malicious ip': ip, 'timestamp': server['timestamp']})

def read_mail_ip_stat_file(provider,stat_file_path, output_dir_path):
    with open(stat_file_path, 'r') as f:
        data = json.load(f)
    mail_server_ips = {}
    for ip, values in data['remote_ip_server_ip_timestamps'].items():
        if is_single_digit_ip(ip):
            continue
        servers = set()
        for value in values:
            server_ip, timestamp = value
            if is_single_digit_ip(server_ip):
                continue
            if ip not in mail_server_ips:
                mail_server_ips[ip] = []
            mail_server_ips[ip].append({'proxy_server_ip': server_ip, 'timestamp': timestamp})
    dir_path = output_dir_path
    csv_file_path = os.path.join(dir_path, f'mail_server_ips_asp_{provider}_samples.csv')

    # Check if the directory exists, if not, create it
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)

    # Open the file in write mode
    with open(csv_file_path, 'w', newline='') as csvfile:
        fieldnames = ['proxy node ip', 'mail server ip', 'timestamp']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for ip, servers in mail_server_ips.items():
            
            for server in servers:
                writer.writerow({'proxy node ip': map_provider_to_docker_ip(provider), 'mail server ip': ip, 'timestamp': server['timestamp']})
                

'''
Visiting gov/edu orgs
'''


visiting_stat_file_path = 'stat.json'

import csv
import json
import os

def read_visiting_orgs_stat_file(stat_file_path, output_path):
    with open(stat_file_path, 'r') as input_json:
        input_stat = json.load(input_json)

    domain_times_filename_No_url_length = input_stat['domain_times_filename_No_url_length']

    if not os.path.exists(output_path):
        os.makedirs(output_path)

    providers_files = {}

    for domain, value0 in domain_times_filename_No_url_length.items():
        for filename, value1 in value0[1].items():
            provider_field = filename.split('_')[0]
            if provider_field not in providers_files:
                output_csv_path = os.path.join(output_path, f"{provider_field}_visiting_sensitive_orgs.csv")
                csvfile = open(output_csv_path, 'w', newline='')
                providers_files[provider_field] = {
                    'csvfile': csvfile,
                    'writer': csv.writer(csvfile)
                }
                providers_files[provider_field]['writer'].writerow(['proxy node IP', 'url', 'server_ip', 'server_port', 'timestamp'])

    for domain, value0 in domain_times_filename_No_url_length.items():
        for filename, value1 in value0[1].items():
            provider_field = filename.split('_')[0]
            writer = providers_files[provider_field]['writer']
            for packet_num, data in value1.items():
                writer.writerow([map_provider_to_docker_ip(provider_field), data[0], data[2][0], data[2][2], data[2][3]])

    for provider in providers_files.values():
        provider['csvfile'].close()
                ## data[0] url
                ## data[1] traffic size
                ## data[2][0] server ip
                ## data[2][1] packet_num
                ## data[2][2] server port
                ## data[2][3] timestamp         
read_visiting_orgs_stat_file("stat.json", "./")
