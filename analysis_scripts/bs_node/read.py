import json

# Variables to count probes and IPs
packetstream_probe_count = 0
iproyal_probe_count = 0
total_probe_count = 0
packetstream_ip_count = 0
iproyal_ip_count = 0
total_ip_count = 0

# Load statistics from JSON files
with open('./stat.json', 'r') as file:
    input_stat = json.load(file)
    ips_16 = input_stat['ips_16']
    ips_24 = input_stat['ips_24']
    dict_x = input_stat['dict_x']
    dict_y = input_stat['dict_y']

with open('./stat2.json', 'r') as file:
    input_stat = json.load(file)
    total_ips_16 = input_stat['ips_16']
    total_ips_24 = input_stat['ips_24']
    total = input_stat['total']
    total_dict_ = input_stat['dict_']

# Calculate probe counts and IP counts
for count in dict_x.values():
    packetstream_probe_count += count
for count in dict_y.values():
    iproyal_probe_count += count
total_probe_count = packetstream_probe_count + iproyal_probe_count

packetstream_ip_count = len(dict_x)
iproyal_ip_count = len(dict_y)
total_ip_count = len(total_dict_)

# Print statistics
print('Scale:')
print('packetstream_ip_count:', packetstream_ip_count)
print('iproyal_ip_count:', iproyal_ip_count)
print('total_ip_count:', total_ip_count)
print('packetstream_probe_count:', packetstream_probe_count)
print('iproyal_probe_count:', iproyal_probe_count)
print('total_probe_count:', total_probe_count, total)
print()

# Relay statistics, IPs anonymized
relay_1_packetstream = dict_x['<anonymized_ip_1>']
relay_1_iproyal = dict_y['<anonymized_ip_1>']
relay_1_total = relay_1_packetstream + relay_1_iproyal
relay_2_packetstream = dict_x['<anonymized_ip_2>']
relay_2_iproyal = dict_y['<anonymized_ip_2>']
relay_2_total = relay_2_packetstream + relay_2_iproyal

print('BS nodes under our control')
print('relay_1_packetstream:', relay_1_packetstream)
print('relay_1_iproyal:', relay_1_iproyal)
print('relay_1_total:', relay_1_total)
print('relay_2_packetstream:', relay_2_packetstream)
print('relay_2_iproyal:', relay_2_iproyal)
print('relay_2_total:', relay_2_total)
print()

# Comparison with previous proxy datasets
with open('./dataset_ip.json', 'r') as file:
    input_stat = json.load(file)
    dataset_ip_num = input_stat['ip_num']

packetstream_hit_count = 0
iproyal_hit_count = 0
total_hit_count = 0
for key in dict_x:
    if key in dataset_ip_num:
        packetstream_hit_count += 1
for key in dict_y:
    if key in dataset_ip_num:
        iproyal_hit_count += 1
for key in total_dict_:
    if key in dataset_ip_num:
        total_hit_count += 1

print('A comparison with previous residential proxy datasets:')
print('dataset_ip_number:', len(dataset_ip_num))
print('packetstream_hit_count:', packetstream_hit_count, 'rate1:', packetstream_hit_count / len(dataset_ip_num), 'rate2:', packetstream_hit_count / len(dict_x))
print('iproyal_hit_count:', iproyal_hit_count, 'rate1:', iproyal_hit_count / len(dataset_ip_num), 'rate2:', iproyal_hit_count / len(dict_y))
print('total_hit_count:', total_hit_count, 'rate1:', total_hit_count / len(dataset_ip_num), 'rate2:', total_hit_count / len(total_dict_))
