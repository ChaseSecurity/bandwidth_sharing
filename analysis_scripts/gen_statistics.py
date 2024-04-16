# %%
import datetime
import dpkt
import os
import socket
import logging
import sys

from tqdm import tqdm
import pandas as pd

# %%
def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except:
        # return False  # 这里因为具体需要把IPv6给丢弃了
        # # 如果希望IPv6也能获取可以这样
        return socket.inet_ntop(socket.AF_INET6,inet)

def get_pcap_size_bytes(filepath) -> int:
    return os.path.getsize(filepath)  # bytes



def convert_bytes(size: int) -> str:
    for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return "%3.1f %s" % (size, x)
        size /= 1024.0
    return size


def file_is_pcap(fileName):
    if fileName.split('.')[-1] == 'pcap':
        return True
    else:
        return False


def get_all_pcaps(dirPath):
    pcaps2process = []
    if not os.path.exists(dirPath):
        return []
    for item_name in os.listdir(dirPath):
        f = os.path.join(dirPath, item_name)
        if os.path.isfile(f) and file_is_pcap(f):
            pcaps2process.append(f)
    return pcaps2process

def get_file_timespan(filePath):
    f = open(filePath, 'rb')
    try:
        pcap = dpkt.pcap.Reader(f)
    except Exception as error:
        logger.info(f"{filePath} failed.")
        logger.error(f"\n{error}")
        invalidTcpdumpHeaderLogger.info(filePath)
        return 0
    start_timestamp = None
    end_timestamp = None
    for ts, buf in pcap:
        if not start_timestamp:
            start_timestamp = (datetime.datetime.utcfromtimestamp(ts))
        else:
            end_timestamp = (datetime.datetime.utcfromtimestamp(ts))
    total_seconds = (end_timestamp-start_timestamp).total_seconds()
    return (total_seconds)



def convert_seconds2days(total_seconds) -> float:
    return float(f"{total_seconds/60/60/24: .2f}")



def get_total_files_days(pcaps2process) -> float:
    total_seconds = 0
    for f in tqdm(pcaps2process, desc='Calculating total files days', leave=True):
        total_seconds += get_file_timespan(f)
    total_days = convert_seconds2days(total_seconds)
    return total_days


def get_provider_name_from_path(filePath) -> str:
    return filePath.split('/')[-1].split('.')[0].split('_')[0].lower()

def get_provider_pcaps(provider_name:str, pcaps2process:list)->list:
    target_files = []
    for pcapPath in pcaps2process:
        if provider_name.lower() == get_provider_name_from_path(pcapPath):
            target_files.append(pcapPath)
    return target_files
def get_provider_total_files_days(provider: str, pcaps2process: list) -> float:
    logger.info(f'Calculating {provider} total files days')
    target_files = []
    for pcapPath in pcaps2process:
        if provider.lower() == get_provider_name_from_path(pcapPath):
            target_files.append(pcapPath)
    return get_total_files_days(target_files)


def get_files_total_bytes(pcaps2process: list) -> int:
    total_size_bytes = 0
    for f in tqdm(pcaps2process, desc='Calculating total files size', leave=True):
        total_size_bytes += get_pcap_size_bytes(f)
    return total_size_bytes


def get_provider_total_files_size_bytes(provider: str, pcaps2process: list) -> int:
    logger.info(f'Calculating {provider} total files size bytes.')
    target_files = []
    for pcapPath in pcaps2process:
        if provider.lower() == get_provider_name_from_path(pcapPath):
            target_files.append(pcapPath)
    return get_files_total_bytes(target_files)


def size2bytes(size: str) -> int:
    # convert x kb, mb, gb to bytes.
    unit = size.split(' ')[1]
    num = int(float(size.split(' ')[0]))
    index = ['bytes', 'KB', 'MB', 'GB', 'TB'].index(unit)
    return num * pow(1024, index)

def get_time_period(target_files: list)->list:
    startDate = ''
    endDate = ''
    for filePaths in target_files:
        date = filePaths.split('/')[-1].split('.')[0].split('_')[2]
        date_info = date.split('-')
        year = date_info[0]
        month = date_info[1]
        day = date_info[2]
        this_date = datetime.date(int(year), int(month), int(day))
        if not startDate:
            startDate = this_date
        else:
            startDate = this_date if this_date < startDate else startDate
        if not endDate:
            endDate = this_date
        else:
            endDate = this_date if this_date > endDate else endDate
    return [startDate, endDate]
        
def get_provider_time_period(provider_name: str, pcaps2process: list)->list:
    startDate = ''
    endDate = ''
    target_files = get_provider_pcaps(provider_name, pcaps2process)
    timePeriod = get_time_period(target_files)
    return timePeriod
def merge_period_results(periods: list)->list:
    startDate = ''
    endDate = ''
    for period in periods:
        if not period[0]:
            continue
        try:
            if not startDate:
                startDate = period[0]
            else:
                startDate = period[0] if period[0] < startDate else startDate
            if not endDate:
                endDate = period[1]
            else:
                endDate = period[1] if period[1] > endDate else endDate
        except Exception as error:
            logger.error(error)
            logger.info(f'startDate:{startDate}, period[0]: {period[0]}, \
                  endDate:{endDate}, period[1]:{period[1]}')
    return [startDate, endDate]
def setup_logger(name, log_file, formatter, level=logging.INFO):
    handler = logging.FileHandler(log_file)
    handler.setFormatter(formatter)
    
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)
    return logger
# %%
def gen_statistics(paths2analyze, stats):
    # ==
    # paths2analyze[0]: us data
    logging.info(f"\n{'='*20}\nOngoing: bs_traffic_us\n{'='*20}")
    us_path = paths2analyze[0]
    pcaps2process = get_all_pcaps(us_path)
    stats.loc['Packetstream US']['Days'] = get_provider_total_files_days(
        'packetstream', pcaps2process)
    stats.loc['Packetstream US']['SizeBytes'] = get_provider_total_files_size_bytes(
        'packetstream', pcaps2process)
    stats.loc['Packetstream US']['Size'] = convert_bytes(
        stats.loc['Packetstream US']['SizeBytes'])
    stats.loc['Packetstream US']['TimePeriod'] = get_provider_time_period('packetstream', pcaps2process)
    stats.loc['Honeygain US']['TimePeriod'] = get_provider_time_period('honeygain', pcaps2process)
    stats.loc['IPRoyal US']['TimePeriod'] = get_provider_time_period('iproyal', pcaps2process)

    stats.loc['Honeygain US']['Days'] = get_provider_total_files_days(
        'honeygain', pcaps2process)
    stats.loc['Honeygain US']['SizeBytes'] = get_provider_total_files_size_bytes(
        'honeygain', pcaps2process)
    stats.loc['Honeygain US']['Size'] = convert_bytes(
        stats.loc['Honeygain US']['SizeBytes'])

    stats.loc['IPRoyal US']['Days'] = get_provider_total_files_days(
        'iproyal', pcaps2process)
    stats.loc['IPRoyal US']['SizeBytes'] = get_provider_total_files_size_bytes(
        'iproyal', pcaps2process)
    stats.loc['IPRoyal US']['Size'] = convert_bytes(
        stats.loc['IPRoyal US']['SizeBytes'])

    logging.info(f"\n{'='*20}\nOngoing: bs_traffic_cn\n{'='*20}")

    cn_path = paths2analyze[1]
    pcaps2process = get_all_pcaps(cn_path)
    stats.loc['Packetstream China']['Days'] = get_provider_total_files_days(
        'packetstream', pcaps2process)
    stats.loc['Packetstream China']['SizeBytes'] = get_provider_total_files_size_bytes(
        'packetstream', pcaps2process)
    stats.loc['Packetstream China']['Size'] = convert_bytes(
        stats.loc['Packetstream China']['SizeBytes'])

    stats.loc['Honeygain China']['Days'] = get_provider_total_files_days(
        'honeygain', pcaps2process)
    stats.loc['Honeygain China']['SizeBytes'] = get_provider_total_files_size_bytes(
        'honeygain', pcaps2process)
    stats.loc['Honeygain China']['Size'] = convert_bytes(
        stats.loc['Honeygain China']['SizeBytes'])

    stats.loc['IPRoyal China']['Days'] = get_provider_total_files_days(
        'iproyal', pcaps2process)
    stats.loc['IPRoyal China']['SizeBytes'] = get_provider_total_files_size_bytes(
        'iproyal', pcaps2process)
    stats.loc['IPRoyal China']['Size'] = convert_bytes(
        stats.loc['IPRoyal China']['SizeBytes'])

    stats.loc['Packetstream China']['TimePeriod'] = get_provider_time_period('packetstream', pcaps2process)
    stats.loc['Honeygain China']['TimePeriod'] = get_provider_time_period('honeygain', pcaps2process)
    stats.loc['IPRoyal China']['TimePeriod'] = get_provider_time_period('iproyal', pcaps2process)

    stats.loc['Packetstream']['Days'] = stats.loc['Packetstream US']['Days'] + \
        stats.loc['Packetstream China']['Days']
    stats.loc['Honeygain']['Days'] = stats.loc['Honeygain US']['Days'] + \
        stats.loc['Honeygain China']['Days']
    stats.loc['IPRoyal']['Days'] = stats.loc['IPRoyal US']['Days'] + \
        stats.loc['IPRoyal China']['Days']
    stats.loc['Overall']['Days'] = stats.loc['Packetstream']['Days'] + \
        stats.loc['Honeygain']['Days'] + stats.loc['IPRoyal']['Days']

    stats.loc['Packetstream']['SizeBytes'] = stats.loc['Packetstream US']['SizeBytes'] + \
        stats.loc['Packetstream China']['SizeBytes']
    stats.loc['Honeygain']['SizeBytes'] = stats.loc['Honeygain US']['SizeBytes'] + \
        stats.loc['Honeygain China']['SizeBytes']
    stats.loc['IPRoyal']['SizeBytes'] = stats.loc['IPRoyal US']['SizeBytes'] + \
        stats.loc['IPRoyal China']['SizeBytes']
    stats.loc['Overall']['SizeBytes'] = stats.loc['Packetstream']['SizeBytes'] + \
        stats.loc['Honeygain']['SizeBytes'] + stats.loc['IPRoyal']['SizeBytes']
    # Overall
    stats.loc['Packetstream']['Size'] = convert_bytes(
        stats.loc['Packetstream']['SizeBytes'])
    stats.loc['Honeygain']['Size'] = convert_bytes(
        stats.loc['Honeygain']['SizeBytes'])
    stats.loc['IPRoyal']['Size'] = convert_bytes(
        stats.loc['IPRoyal']['SizeBytes'])
    stats.loc['Overall']['Size'] = convert_bytes(
        stats.loc['Packetstream']['SizeBytes'] + stats.loc['Honeygain']['SizeBytes'] + stats.loc['IPRoyal']['SizeBytes'])

    stats.loc['Packetstream']['TimePeriod'] = merge_period_results([stats.loc['Packetstream US']['TimePeriod'], stats.loc['Packetstream China']['TimePeriod']])
    stats.loc['Honeygain']['TimePeriod'] = merge_period_results([stats.loc['Honeygain US']['TimePeriod'], stats.loc['Honeygain China']['TimePeriod']])
    stats.loc['IPRoyal']['TimePeriod'] = merge_period_results([stats.loc['IPRoyal US']['TimePeriod'], stats.loc['IPRoyal China']['TimePeriod']])
    stats.loc['Overall']['TimePeriod'] = merge_period_results([stats.loc['Packetstream']['TimePeriod'], stats.loc['Honeygain']['TimePeriod'], stats.loc['IPRoyal']['TimePeriod']])


# %%
if __name__ == "__main__":
    cnDataDirPath = '/data2/bs/bs_traffic_cn'
    usDataDirPath = "/data2/bs/bs_traffic_us"

    # Configure logger
    # logging.basicConfig(filename='gen_statistics.log', filemode='w',level=logging.INFO, format='%(asctime)s %(message)s')
    logger = setup_logger('logger1', 'script.log', logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    invalidTcpdumpHeaderLogger = setup_logger('logger2', 'invalidTcpdumpHeader.log', logging.Formatter('%(message)s'))
    
    col_names = ['TimePeriod', 'Days', 'Size', 'SizeBytes']
    row_names = ['Packetstream', 'Packetstream China', 'Packetstream US',
                    'IPRoyal', 'IPRoyal China', 'IPRoyal US',
                    'Honeygain', 'Honeygain US', 'Honeygain China',
                    'Overall']
    df = pd.DataFrame(index=row_names, columns=col_names)
    paths2analyze = [usDataDirPath, cnDataDirPath]
    gen_statistics(paths2analyze, df)
    df.to_csv('statistics.csv')
    logger.info(f'\n{df}')
