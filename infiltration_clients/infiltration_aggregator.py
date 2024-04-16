import os, sys
import json
import argparse
from collections import defaultdict
import pandas as pd
import datetime
import logging
import re

class InfilAgg(object):
    def __init__(
        self,
        src_dir,
        result_dir,
        date_format=None,
        start_ds=None,
        end_ds=None,
    ):
        self.src_dir = src_dir
        self.result_dir = result_dir
        self.date_format = date_format if date_format else '%Y%m%d'
        last_ds = datetime.datetime.strftime(
            datetime.datetime.now() -  datetime.timedelta(days=1),
            self.date_format,
        )
        self.start_ds = start_ds if start_ds else last_ds
        self.end_ds = end_ds if end_ds else last_ds
        self.ip_set = set()
        # ip as key, (provider, timestamp) as value
        self.ip_to_provider_timestamp_dict = defaultdict(set)
        self.provider_to_ip_dict = defaultdict(set)
        self.result_date_file = os.path.join(
            result_dir,
            'aggregation_dates.txt'
        )
        self.result_ip_file = os.path.join(
            result_dir,
            'aggregation_ips.json',
        )
        self.result_ip_only_file = os.path.join(
            result_dir,
            'aggregation_only_ips.tsv',
        )
        self.result_stat_file = os.path.join(
            result_dir,
            'aggregation_stats.txt',
        )

    def aggregate(self):
        # check and load historical aggregration
        ds_list = []
        start_date = datetime.datetime.strptime(self.start_ds, self.date_format)
        end_date = datetime.datetime.strptime(self.end_ds, self.date_format)
        curr_date = start_date
        day_delta = datetime.timedelta(days=1)
        while curr_date <= end_date:
            ds_list.append(curr_date.strftime(self.date_format))
            curr_date += day_delta
        logging.info(
            'Aggregate %d dates between %s and %s',
            len(ds_list),
            self.start_ds,
            self.end_ds,
        )
        agg_dates = set()
        if os.path.exists(self.result_date_file):
            with open(self.result_date_file, 'r') as fd:
                for line in fd:
                    line = line.strip()
                    curr_date = datetime.datetime.strptime(
                        line,
                        self.date_format,
                    )
                    agg_dates.add(line)
        if len(agg_dates):
            self.load_last_agg()
        # load uncovered periods
        dates_to_agg = list(set(ds_list) - agg_dates)
        logging.info(
            '%d aggregated, %d left to finish',
            len(set(agg_dates)),
            len(dates_to_agg),
        )
        for ds in ds_list:
            if ds in agg_dates:
                continue
            src_file = os.path.join(
                self.src_dir,
                ds,
                'logs/infiltration_results.json',
            )
            if not os.path.exists(src_file):
                logging.warning(
                    'file not found: %s',
                    ds,
                )
                continue
            with open(src_file, 'r') as fd:
                for line in fd:
                    try:
                        request_obj = json.loads(line.strip())
                    except Exception as e:
                        logging.warning(
                            'error when parsing request %s',
                            line,
                        )
                        continue
                    ip = request_obj['ip']
                    timestamp = request_obj['timestamp']
                    provider = request_obj['source']
                    self.ip_set.add(ip)
                    self.ip_to_provider_timestamp_dict[ip].add(
                        (provider, timestamp)
                    )
                    self.provider_to_ip_dict[provider].add(ip)
        # dump and stats
        with open(self.result_ip_file, 'w') as fd:
            for ip in self.ip_set:
                provider_timestamps = self.ip_to_provider_timestamp_dict[ip]
                ip_item = {
                    'ip': ip,
                    'provider_timestamps': list(provider_timestamps),
                }
                fd.write(
                    json.dumps(ip_item) + '\n'
                )
        with open(self.result_ip_only_file, 'w') as fd:
            for ip in self.ip_set:
                fd.write(ip + '\n')
        with open(self.result_date_file, 'w') as fd:
            for ds in ds_list:
                fd.write(ds + '\n')

        # generate result stats
        columns = [
            'provider',
            'start date',
            'end date',
            '# IPs',
            '# IPv4',
            '# IPv6',
        ]
        rows = []
        rows.append([
            'All',
            self.start_ds,
            self.end_ds,
            len(self.ip_set),
            sum([1 for ip in self.ip_set if ':' not in ip]),
            sum([1 for ip in self.ip_set if ':' in ip]),
        ])
        provider_ids = sorted(self.provider_to_ip_dict.keys())
        global global_provider_tag_name_dict
        for provider_id in provider_ids:
            provider_name = global_provider_tag_name_dict[provider_id]
            ip_set = self.provider_to_ip_dict[provider_id]
            rows.append([
                provider_name,
                self.start_ds,
                self.end_ds,
                len(ip_set),
                sum([1 for ip in ip_set if ':' not in ip]),
                sum([1 for ip in ip_set if ':' in ip]),
            ])
        stat_df = pd.DataFrame(
            data=rows,
            columns=columns,
        )
        with open(self.result_stat_file, 'w') as fd:
            fd.write(stat_df.to_string() + '\n')
            logging.info(stat_df.to_string())


    def load_last_agg(self):
        if not os.path.exists(self.result_ip_file):
            return
        with open(self.result_ip_file, 'r') as fd:
            for line in fd:
                ip_obj = json.loads(line.strip())
                ip = ip_obj['ip']
                provider_timestamps_old = ip_obj['provider_timestamps']
                provider_timestamps = []
                for item in provider_timestamps_old:
                    provider_timestamps.append((item[0], item[1]))
                self.ip_set.add(ip)
                self.ip_to_provider_timestamp_dict[ip] |= set(provider_timestamps)
                for provider, timestamp in provider_timestamps:
                    self.provider_to_ip_dict[provider].add(ip)
        return


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    date_format = '%Y%m%d'
    today_ds = datetime.datetime.now().strftime(date_format)
    parser = argparse.ArgumentParser()
    parser.add_argument('src_dir', type=str)
    parser.add_argument('result_dir', type=str)
    parser.add_argument('proxy_provider_name_id_file', type=str)
    parser.add_argument('-sd', '--start_date', type=str, default=None)
    parser.add_argument('-ed', '--end_date', type=str, default=None)
    options = parser.parse_args()
    p_file = options.proxy_provider_name_id_file
    src_dir = options.src_dir
    result_dir = options.result_dir
    start_ds = options.start_date
    end_ds = options.end_date
    if not os.path.exists(result_dir):
        os.makedirs(result_dir)
    sep_re = re.compile('[ \t\n\r,]+', re.I)
    with open(p_file, 'r') as fd:
        for line in fd:
            attrs = sep_re.split(line.strip())
            id = int(attrs[0])
            name = attrs[1]
            global_provider_tag_name_dict[id] = name
    logging.info('got %d providers', len(global_provider_tag_name_dict))
    infil_agg = InfilAgg(
        src_dir=src_dir,
        result_dir=result_dir,
        date_format='%Y%m%d',
        start_ds=start_ds,
        end_ds=end_ds,
    )
    infil_agg.aggregate()
