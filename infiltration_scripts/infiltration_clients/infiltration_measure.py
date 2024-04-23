import os, sys
import json
import argparse
from collections import defaultdict
import pandas as pd
import datetime
import logging
import re
global_provder_tag_name_dict = {
    1: 'intoli.com',
    2: 'smartproxy.com',
    3: 'cosmoproxy.com',
    4: 'netnut.io',
}
''' request example
{"startTime": 1556036704.8493183, "endTime": 1556036705.6670942, "ip": "75.45.199.167", "timestamp": 1556036704.8493183, "url": "http://edfd7f6b-01-1556036704.mpaas.shop/aesclick1/edfd7f6b-e6d3-4fbd-b395-384f07bac4b9", "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.22 Safari/537.36", "port": "54689", "xRequestId": "edfd7f6b-e6d3-4fbd-b395-384f07bac4b9", "id": "edfd7f6b-e6d3-4fbd-b395-384f07bac4b9", "proxies": {"http": "http://1762fc7039a56b9b:1dd00e11fc23af3c@proxy.intoli.com:80", "https": "http://1762fc7039a56b9b:1dd00e11fc23af3c@proxy.intoli.com:80"}, "requestTime": 1556036705.497, "responseHeader": "{\"transfer-encoding\": \"chunked\", \"server\": \"Apache/2.4.29 (Ubuntu)\", \"vary\": \"Accept-Encoding\", \"date\": \"Tue, 23 Apr 2019 16:25:05 GMT\", \"keep-alive\": \"timeout=5, max=100\", \"content-type\": \"text/html; charset=UTF-8\", \"content-encoding\": \"identity\", \"connection\": \"close\"}", "source": 1}
'''
def ip_stats(result_files):
    request_count_by_provider = defaultdict(int)
    ip_by_provider = defaultdict(set)
    ipv4_by_provider = defaultdict(set)
    ipv6_by_provider = defaultdict(set)
    global global_provder_tag_name_dict
    for result_file in result_files:
        with open(result_file, 'r') as fd:
            for line in fd:
                request = json.loads(line.strip())
                ip = request['ip']
                provider_tag = request['source']
                provider_name = global_provder_tag_name_dict[provider_tag]
                provider_list = [provider_name, 'all']
                for provider in provider_list:
                    request_count_by_provider[provider] += 1
                    ip_by_provider[provider].add(ip)
                    if ':' not in ip:
                        ipv4_by_provider[provider].add(ip)
                    else:
                        ipv6_by_provider[provider].add(ip)
    columns = [
        'provider',
        '# requests',
        '# uniq IP',
        '# uniq IPv4',
        '# uniq IPv6',
    ]
    sorted_provider_request_list = sorted(
        request_count_by_provider.items(), 
        key=lambda item: item[1],
    )
    rows = []
    for provider, request_count in sorted_provider_request_list:
        rows.append(
            [
                provider,
                request_count,
                len(ip_by_provider[provider]),
                len(ipv4_by_provider[provider]),
                len(ipv6_by_provider[provider]),
            ]
        )
    result_df = pd.DataFrame(
        data=rows,
        columns=columns,
    )
    print(result_df.to_string())
'''
{"banners": [{"banner": "Exception: Connection Timeout", "service": "http", "banner_end_time": 1556125818.2525406, "is_response": false, "port": 80, "transport": "tcp", "banner_start_time": 1556125816.2503352}, {"banner": "Exception: Connection Timeout", "service": "https", "banner_end_time": 1556125820.254674, "is_response": false, "port": 443, "transport": "tcp", "banner_start_time": 1556125818.2525465}, {"banner": "Exception: Connection Timeout", "service": "ssh", "banner_end_time": 1556125822.2568307, "is_response": false, "port": 22, "transport": "tcp", "banner_start_time": 1556125820.2546804}, {"banner": "Exception: Connection Timeout", "service": "ftp", "banner_end_time": 1556125824.2589746, "is_response": false, "port": 21, "transport": "tcp", "banner_start_time": 1556125822.2568378}, {"banner": "Exception: Connection Timeout", "service": "telnet", "banner_end_time": 1556125826.261112, "is_response": false, "port": 23, "transport": "tcp", "banner_start_time": 1556125824.2589803}, {"banner": "Exception: Connection Timeout", "service": "rtsp", "banner_end_time": 1556125828.2632527, "is_response": false, "port": 554, "transport": "tcp", "banner_start_time": 1556125826.2611182}], "is_sticky_proxy": false, "banner_grabbing_end_time": 1556125828.2632606, "requestTime": 1556125807.489, "ip": "98.191.183.30", "timestamp": 1556125806.6816838, "source": 1, "xRequestId": "c8c58fb5-76f6-41b3-98ae-46adeb203333", "endTime": 1556125807.7083464, "proxies": {"https": "http://1762fc7039a56b9b:1dd00e11fc23af3c@proxy.intoli.com:80", "http": "http://1762fc7039a56b9b:1dd00e11fc23af3c@proxy.intoli.com:80"}, "startTime": 1556125806.6816838, "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36", "responseHeader": "{\"vary\": \"Accept-Encoding\", \"content-type\": \"text/html; charset=UTF-8\", \"date\": \"Wed, 24 Apr 2019 17:10:07 GMT\", \"keep-alive\": \"timeout=5, max=100\", \"connection\": \"close\", \"server\": \"Apache/2.4.29 (Ubuntu)\", \"content-encoding\": \"identity\", \"transfer-encoding\": \"chunked\"}", "port": "59294", "banner_grabbing_start_time": 1556125816.2503324, "id": "c8c58fb5-76f6-41b3-98ae-46adeb203333", "url": "http://c8c58fb5-01-1556125806.mpaas.shop/aesclick1/c8c58fb5-76f6-41b3-98ae-46adeb203333", "is_banner_grabbing_success": true}
'''
def ofp_stats(result_files):
    request_count_by_provider = defaultdict(int)
    ip_by_provider = defaultdict(set)
    ipv4_by_provider = defaultdict(set)
    ipv6_by_provider = defaultdict(set)
    succ_request_count_by_provider = defaultdict(int)
    succ_ip_by_provider = defaultdict(set)
    succ_ipv4_by_provider = defaultdict(set)
    succ_ipv6_by_provider = defaultdict(set)
    global global_provder_tag_name_dict
    for result_file in result_files:
        with open(result_file, 'r') as fd:
            for line in fd:
                request = json.loads(line.strip())
                ip = request['ip']
                provider_tag = request['source']
                provider_name = global_provder_tag_name_dict[provider_tag]
                is_response = False
                for banner_item in request['banners']:
                    banner = banner_item['banner']
                    if len(banner) == 0 or banner.startswith('Exception:'):
                        continue
                    is_response = True
                provider_list = [provider_name, 'all']
                for provider in provider_list:
                    request_count_by_provider[provider] += 1
                    ip_by_provider[provider].add(ip)
                    if ':' not in ip:
                        ipv4_by_provider[provider].add(ip)
                    else:
                        ipv6_by_provider[provider].add(ip)
                if not is_response:
                    continue
                provider_list = [provider_name, 'all']
                for provider in provider_list:
                    succ_request_count_by_provider[provider] += 1
                    succ_ip_by_provider[provider].add(ip)
                    if ':' not in ip:
                        succ_ipv4_by_provider[provider].add(ip)
                    else:
                        succ_ipv6_by_provider[provider].add(ip)
    columns = [
        'provider',
        '# requests',
        '# uniq IP',
        '# uniq IPv4',
        '# uniq IPv6',
    ]
    sorted_provider_request_list = sorted(
        request_count_by_provider.items(), 
        key=lambda item: item[1],
    )
    rows = []
    for provider, request_count in sorted_provider_request_list:
        rows.append(
            [
                provider,
                request_count,
                len(ip_by_provider[provider]),
                len(ipv4_by_provider[provider]),
                len(ipv6_by_provider[provider]),
            ]
        )
    result_df = pd.DataFrame(
        data=rows,
        columns=columns,
    )
    print('# OFP overall stat')
    print(result_df.to_string())
    rows = []
    for provider, request_count in sorted_provider_request_list:
        rows.append(
            [
                provider,
                succ_request_count_by_provider[provider],
                len(succ_ip_by_provider[provider]),
                len(succ_ipv4_by_provider[provider]),
                len(succ_ipv6_by_provider[provider]),
            ]
        )
    result_df = pd.DataFrame(
        data=rows,
        columns=columns,
    )
    print('# OFP success stat')
    print(result_df.to_string())

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    date_format = '%Y%m%d'
    today_ds = datetime.datetime.now().strftime(date_format)
    parser = argparse.ArgumentParser()
    parser.add_argument('result_base_dir', type=str)
    parser.add_argument('proxy_provider_name_id_file', type=str)
    parser.add_argument('-sd', '--start_date', type=str, default=today_ds)
    parser.add_argument('-ed', '--end_date', type=str, default=today_ds)
    options = parser.parse_args()
    result_base_dir = options.result_base_dir
    p_file = options.proxy_provider_name_id_file
    start_ds = options.start_date
    end_ds = options.end_date
    logging.info(
        'start-end: %s-%s',
        start_ds,
        end_ds,
    )
    sep_re = re.compile('[ \t\n\r,]+', re.I)
    with open(p_file, 'r') as fd:
        for line in fd:
            attrs = sep_re.split(line.strip())
            id = int(attrs[0])
            name = attrs[1]
            global_provder_tag_name_dict[id] = name
    logging.info('got %d providers', len(global_provder_tag_name_dict))
    result_dirs = []
    start_date = datetime.datetime.strptime(start_ds, date_format)
    end_date = datetime.datetime.strptime(end_ds, date_format)
    day_delta = datetime.timedelta(days=1)
    curr_date = start_date
    while curr_date <= end_date:
        curr_ds = curr_date.strftime(date_format)
        result_dir = os.path.join(
            result_base_dir,
            curr_ds,
        )
        curr_date += day_delta
        if not os.path.exists(result_dir):
            continue
        result_dirs.append(result_dir)
    if len(result_dirs) == 0:
        logging.warning('no exist dirs found')
        sys.exit(1)
    else:
        logging.info('%d dirs found', len(result_dirs))
    ip_stats(
        [
            os.path.join(
                result_dir,
                'logs/infiltration_results.json'
            )
            for result_dir in result_dirs
        ]
    )
    ofp_stats(
        [
            os.path.join(
                result_dir,
                'ofp/infiltration_ofp_results.json'
            )
            for result_dir in result_dirs
        ]
    )
