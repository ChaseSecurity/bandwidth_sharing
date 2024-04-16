import os
import json

'''
This script counts the number of IP addresses captured by PacketStream every day
and the total number of IP addresses captured.
'''

ips_24 = [{}, {}]
ips_16 = [{}, {}]

def get_files():
    return os.listdir(r'/data2/bs/classbydate')

def process_files(filenames):
    total_packetstream = 0
    total_iproyal = 0
    dict_packetstream = {}
    dict_iproyal = {}

    for filename in filenames:
        with open(f'/data2/bs/classbydate/{filename}', 'r') as file:
            for line in file:
                line_data = json.loads(line)
                proxy = line_data["proxies"]
                ip = line_data['ip']
                ip_24 = ip[:ip.rfind('.')]
                ip_16 = ip[:ip[:ip.rfind('.')].rfind('.')]

                # Anonymize proxy URL
                if proxy['http'] == "http://<username>:<password>@proxy.packetstream.io:31112":
                    total_packetstream += 1
                    if ip not in dict_packetstream:
                        dict_packetstream[ip] = 1
                    else:
                        dict_packetstream[ip] += 1

                    ips_24[0][ip_24] = ips_24[0].get(ip_24, 0) + 1
                    ips_16[0][ip_16] = ips_16[0].get(ip_16, 0) + 1
                else:
                    total_iproyal += 1
                    if ip not in dict_iproyal:
                        dict_iproyal[ip] = 1
                    else:
                        dict_iproyal[ip] += 1

                    ips_24[1][ip_24] = ips_24[1].get(ip_24, 0) + 1
                    ips_16[1][ip_16] = ips_16[1].get(ip_16, 0) + 1

            print(f'{filename} processing completed.')

    return total_packetstream, dict_packetstream, total_iproyal, dict_iproyal

def write_json(filename, data):
    with open(filename, 'w') as f:
        json.dump(data, f)

def write_line_json(filename, data):
    with open(filename, 'w') as f:
        for item in data:
            json_string = json.dumps(item)
            f.write(json_string + '\n')
            f.flush()

# Main execution
filenames = get_files()
total_packetstream, dict_packetstream, total_iproyal, dict_iproyal = process_files(filenames)

print('PacketStream total IP number:', total_packetstream)
print('PacketStream unique IP number:', len(dict_packetstream))
print('IPRoyal total IP number:', total_iproyal)
print('IPRoyal unique IP number:', len(dict_iproyal))
print('IPs 16:', ips_16)
print('IPs 24:', ips_24)

output_stat = {'ips_16': ips_16, 'ips_24': ips_24, 'dict_x': dict_packetstream, 'dict_y': dict_iproyal}
write_json('./stat.json', output_stat)
write_line_json('./packetstream.json', dict_packetstream.keys())
write_line_json('./iproyal.json', dict_iproyal.keys())
