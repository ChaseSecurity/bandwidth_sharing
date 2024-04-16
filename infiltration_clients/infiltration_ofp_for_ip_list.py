#!/usr/bin/python
''' log all mq results to local filesystem, and optionally database
'''
#read msg from backup queues of al/fp requests, write to files for different dates
import argparse
import os,sys
import json
import logging
import time
import datetime
import traceback
import threading
from threading import Thread
from queue import Queue
from threading import Lock
import fp_probe as fpp

global_result_queue = Queue()
global_message_buffer = Queue()
global_message_lock = threading.Lock()
global_is_stop = False

def result_dump(
    result_file,
    interval=5,
):
    global global_result_queue
    global global_is_stop
    result_count = 0
    start_time = time.time()
    result_fd = open(result_file, 'a')
    while True:
        try:
            if result_count > 0 and result_count % 1000 == 0:
                logging.info(
                    'dumped %d result items with time cost %d seconds',
                    result_count,
                    time.time() - start_time,
                )
            is_empty = global_result_queue.empty()
            if is_empty and global_is_stop:
                time.sleep(interval)
                is_empty = global_result_queue.empty()
                if is_empty and global_is_stop:
                    logging.info('it is time to quit the thread of result dumping')
                    break
            if is_empty:
                logging.info('sleep to wait for result items with %d dumped', result_count)
                time.sleep(interval)
                continue
            # get message and flush to local files
            result_item = global_result_queue.get_nowait()
            if type(result_item) is bytes:
                result_item = result_item.decode('utf-8')
            result_fd.write(json.dumps(result_item) + '\n')
            result_fd.flush()
        except Exception as e:
            logging.warning(
                'error when dumping results with exception %s and traceback %s',
                e,
                traceback.format_exc(),
            )
            print('result_item' + result_item)
            time.sleep(interval)
            continue
    result_fd.close()
    logging.info(
        'quit result dump with %d results dumped',
        result_count,
    )


def initLogging(resultDir):
    logFile = os.path.join(resultDir, "logFile")
    #initialize logging
    loggingFormat = "%(levelname)s-%(name)s-%(asctime)s-<%(message)s>-%(threadName)s-%(processName)s-%(lineno)d-%(filename)s"
    formatter = logging.Formatter(loggingFormat)
    streamHandler = logging.StreamHandler(sys.stdout)
    streamHandler.setLevel(logging.INFO)
    streamHandler.setFormatter(formatter)
    fileHandler = logging.FileHandler(logFile)
    fileHandler.setFormatter(formatter)
    fileHandler.setLevel(logging.WARNING)
    logger = logging.getLogger("")
    logger.setLevel(logging.DEBUG)
    logger.addHandler(streamHandler)
    logger.addHandler(fileHandler)
    return logger

def outside_fp(
    result_file,
    interval=5,
):
    global global_result_queue
    global global_message_buffer
    global global_message_lock
    global global_is_stop
    fp_count = 0
    start_time = time.time()
    try:
        while True:
            if fp_count > 0 and fp_count % 1000 == 0:
                logging.info(
                    'dumped %d result items with time cost %d seconds',
                    fp_count,
                    time.time() - start_time,
                )
            global_message_lock.acquire()
            is_empty = global_message_buffer.empty()
            if is_empty and global_is_stop:
                time.sleep(interval)
                is_empty = global_message_buffer.empty()
                if is_empty and global_is_stop:
                    logging.info('it is time to quit the thread of result dumping')
                    global_message_lock.release()
                    break
            if is_empty:
                global_message_lock.release()
                time.sleep(interval)
                continue
            # get message and flush to local files
            msg_json = global_message_buffer.get_nowait()
            global_message_lock.release()
            if type(msg_json) is bytes:
                msg_json = msg_json.decode('utf-8')
            msg_list = json.loads(msg_json)
            for msg_item in msg_list:
                host = msg_item.get('ip', None)
                id = msg_item.get('id', None)
                if host is None:
                    logging.warning('invalide message without IP address: %s', msg_item)
                    continue
                try:
                    banner_batch_start_time = time.time()
                    banner_list = fpp.banner_grab_batch(host)
                    banner_batch_end_time = time.time()
                    msg_item['is_banner_grabbing_success'] = True
                    msg_item['banner_grabbing_start_time'] = banner_batch_start_time
                    msg_item['banner_grabbing_end_time'] = banner_batch_end_time
                    msg_item['banners'] = banner_list
                except Exception as e:
                    logging.warning(
                        'fail to grab banner for host %s, id %s, with error %s',
                        host,
                        id,
                        e,
                    )
                    msg_item['is_banner_grabbing_success'] = False
                global_result_queue.put(msg_item)
                fp_count += 1
    except Exception as e:
        logging.warning(
            'error when outside fingerprinting with exception %s and traceback %s',
            e,
            traceback.format_exc(),
        )
        logging.warning('quit fingerprinting with error')
        global_is_stop = True

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("ip_file", type = str)
    parser.add_argument("resultDir", type = str)
    parser.add_argument("-ntfp", '--num_threads_fp', type = int, default = 5) # finterprinting interval in hours
    parser.add_argument('-to', '--timeout', type=float, default=80000)
    options = parser.parse_args()
    ip_file = options.ip_file
    resultDir = options.resultDir
    if not os.path.exists(resultDir):
        os.makedirs(resultDir)
    initLogging(resultDir)
    # load ips
    ips = set()
    with open(ip_file, 'r') as fd:
        for line in fd:
            ips.add(line.strip())
    logging.info('loaded %d ips', len(ips))
    thread_num_fp = options.num_threads_fp
    ofp_worker_list = []
    for i in range(thread_num_fp):
        worker = threading.Thread(
            target=outside_fp,
            args=(
                os.path.join(
                    resultDir,
                    'infiltration_ofp_results.json',
                ),
            ),
        )
        ofp_worker_list.append(worker)
    logging.info(
        'set up %d workers to conduct outside fingerprinting',
        len(ofp_worker_list),
    )
    result_dump_thread = threading.Thread(
        target=result_dump,
        args=(
            os.path.join(
                resultDir,
                'infiltration_ofp_results.json',
            ),
        ),
        kwargs=dict(
            interval=5,
        ),
    )
    result_dump_thread.start()
    for worker in ofp_worker_list:
        worker.start()
    start_time = time.time()
    q_limit = 10000
    while True:
        q_size = global_message_buffer.qsize()
        if q_size < q_limit:
            for i in range(q_limit - q_size):
                if len(ips) > 0:
                    ip = ips.pop()
                    fp_item = {
                        'id': ip,
                        'ip': ip,
                    }
                    global_message_buffer.put(json.dumps([fp_item]))

        if global_message_buffer.qsize() == 0 and len(ips) == 0:
            time.sleep(5)
            global_is_stop = True
            logging.info('it is time to quit')
            break

        if options.timeout and (time.time()  - start_time) >= options.timeout:
            global_is_stop = True
            logging.info('it is time to quit')
            break
        else:
            time.sleep(5)
    global_is_stop = True
    result_dump_thread.join()
    for worker in ofp_worker_list:
        worker.join()
    logging.info('globally exit')
