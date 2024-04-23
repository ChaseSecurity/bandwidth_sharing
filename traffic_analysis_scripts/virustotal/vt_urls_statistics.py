import json


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

filename = 'result.json'
total = set()
with open(filename, 'r') as f:
    count = 0
    for line in f:
        data = json.loads(line)
        try:
            url = data['data']['id']
            print(url)
            if url not in total:
                total.add(url)
            total_votes = (data['data']['attributes']["total_votes"])
            max_vote_value, label = get_max_value_and_key_from_dict(total_votes)
            if label == 'suspicious' or label == 'malicious':
                count += 1
                print(url, label)
        except Exception as e:
            # print(e)
            # print(data)
            try:
                url = data["url"]
                if url not in total:
                    total.add(url)
            except:
                pass
            
    try:
        print(f"malicious: {count}, total: {len(total)}, account for: {count / len(total)}")
    except ZeroDivisionError:
        print(f"malicious: {count}, total: {len(total)}")
        # print_dict_keys_recursively(data)
        # break
    
        # print(type(data))
        # print(data.keys())

