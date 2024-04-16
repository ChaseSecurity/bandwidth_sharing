import json
import pickle
from collections import defaultdict
def print_dict_keys_recursively(d, indent=0):
    for key, value in d.items():
        print(f'-' * indent + str(key))
        if isinstance(value, dict):
            print_dict_keys_recursively(value, indent + 2)
def get_max_value_of_dict(d):
    max_value = float('-inf')
    for key, value in d.items():
        if isinstance(value, int):
            max_value = max(max_value, value)
        elif isinstance(value, dict):
            max_value = max(max_value, get_max_value_of_dict(value))
    return max_value
def get_max_value_and_key_from_dict(d):
    max_value = float('-inf')
    max_key = None
    for key, value in d.items():
        if isinstance(value, int):
            if value > max_value:
                max_value = value
                max_key = key
        elif isinstance(value, dict):
            result = get_max_value_and_key_from_dict(value)
            if result[0] > max_value:
                max_value = result[0]
                max_key = result[1]
    return (max_value, max_key)

filename = 'oout.json'
total = set()
vt_malicious_ips_dict = defaultdict(set) # tag: ips
vt_malicious_ips = set()
with open(filename, 'r') as f:
    count = 0
    for line in f:
        data = json.loads(line)
        try:
            ip = data['data']['id']
            if ip not in total:
                total.add(ip)
            total_votes = (data['data']['attributes']["total_votes"])
            max_vote_value, label = get_max_value_and_key_from_dict(total_votes)
            
            if label == 'malicious':
                vt_malicious_ips_dict[label].add(ip)
                vt_malicious_ips.add(ip)
                count += 1
                # print(ip, label)
        except Exception as e:
            print(e)
            print(data)
    print(f"malicious: {count}, total: {len(total)}, account for {count / len(total)}")
    with open('vt_malicious_ips.pkl', 'wb') as handle:
        pickle.dump(vt_malicious_ips, handle, protocol=pickle.HIGHEST_PROTOCOL)
        # print_dict_keys_recursively(data)
        # break
    
        # print(type(data))
        # print(data.keys())

