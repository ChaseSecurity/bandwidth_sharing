import json

def process_ip_data(file_path, ip_num):
    """
    Process each line in the given file to count occurrences of each IP address.
    Assumes each line in the file contains a single IP or a JSON object with an 'ip' key.
    """
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            try:
                # Attempt to parse line as JSON
                data = json.loads(line)
                ip = data['ip']
            except json.JSONDecodeError:
                # Handle lines that are not JSON (i.e., plain IP addresses)
                ip = line

            if ip in ip_num:
                ip_num[ip] += 1
            else:
                ip_num[ip] = 1

def main():
    ip_num = {}
    # Process different datasets
    process_ip_data('IP_Groups_Providers.json', ip_num)
    process_ip_data('proxy_IPs.tsv', ip_num)
    process_ip_data('ip_captured_as_web_proxy.tsv', ip_num)

    # Write results to JSON file
    with open('./dataset_ip.json', 'w') as output_json:
        json.dump({'ip_num': ip_num}, output_json)

if __name__ == "__main__":
    main()
