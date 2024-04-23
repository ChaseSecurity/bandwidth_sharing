import json

def load_stats():
    try:
        with open('stat.json', 'r') as input_json:
            input_stat = json.load(input_json)
            all_base_tcp_len = input_stat.get('all_base_tcp_len', 0)
            domain_len = input_stat.get('domain_len', {})
    except FileNotFoundError:
        print("Stat JSON file not found.")
        all_base_tcp_len = 0
        domain_len = {}
    except json.JSONDecodeError:
        print("Error decoding JSON.")
        all_base_tcp_len = 0
        domain_len = {}
    return all_base_tcp_len, domain_len

def process_domains(domain_len):
    stat_len = 0
    cata_len = {}
    try:
        with open('label_domains.txt', 'r') as domains_file:
            for line in domains_file:
                line = line.strip()
                comma_index = line.find(',')
                if comma_index != -1 and line[comma_index + 1:] in domain_len:
                    domain = line[:comma_index]
                    category = line[comma_index + 1:]
                    domain_length = domain_len.get(domain, 0)
                    stat_len += domain_length
                    if category in cata_len:
                        cata_len[category] += domain_length
                    else:
                        cata_len[category] = domain_length
    except FileNotFoundError:
        print("Domains file not found.")
    return stat_len, cata_len

def write_output(all_base_tcp_len, domain_len, stat_len, cata_len):
    try:
        with open('cata_len.txt', 'w') as out_txt:
            proxy_traffic = domain_len.get('proxy.packetstream.io', 0) + domain_len.get('api.packetstream.io', 0)
            out_txt.write(f'总TCP流量:{all_base_tcp_len}\n')
            out_txt.write(f'代理流量:{proxy_traffic},代理流量占总流量比例:{round(proxy_traffic * 100.0 / all_base_tcp_len, 2)}%\n')
            out_txt.write(f'除去代理流量:{all_base_tcp_len - proxy_traffic}\n')
            out_txt.write(f'统计类别流量:{stat_len},占除去代理流量:{round(stat_len * 100 / (all_base_tcp_len - proxy_traffic), 2)}%\n\n')
            sorted_cata_len = sorted(cata_len.items(), key=lambda x: x[1], reverse=True)
            for category, length in sorted_cata_len:
                out_txt.write(f'{category},占比例:{round(length * 100.0 / stat_len, 2)}%\n')
    except IOError:
        print("Error writing to output file.")

def main():
    all_base_tcp_len, domain_len = load_stats()
    stat_len, cata_len = process_domains(domain_len)
    write_output(all_base_tcp_len, domain_len, stat_len, cata_len)

if __name__ == '__main__':
    main()
