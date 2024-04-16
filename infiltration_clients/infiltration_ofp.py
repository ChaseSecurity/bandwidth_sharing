#!/usr/bin/python
''' log all mq results to local filesystem, and optionally database
'''
#read msg from backup queues of al/fp requests, write to files for different dates
import argparse
import os,sys
import mqUtil
import json
import logging
import time
import datetime
import traceback
import threading
from threading import Thread
from queue import Queue
from threading import Lock
from yaml import load, dump
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper
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

def message_consumer(mq_config_file, timeout=80000, queue_size_limit=10000):
    global global_is_stop
    global global_message_buffer
    mq_config_str = open(mq_config_file, 'r').read()
    mq_config_obj = load(mq_config_str, Loader)
    mqClient = mqUtil.MqClient(
        host=mq_config_obj['host'],
        port=mq_config_obj['port'],
        user=mq_config_obj['user'],
        passwd=mq_config_obj['passwd'],
        virtualHost=mq_config_obj['virtual_host'],
        heartbeat=mq_config_obj['heartbeat'],
    )
    try:
        mqConn = mqClient.initNewConn()
        mqChannel = mqClient.initNewChannel()
    except Exception as e:
        logging.warning('set up mq connection failed: %s', e)
        return
    message_count = 0
    start_time = time.time()
    while True:
        try:
            queue_size = global_message_buffer.qsize()
            if queue_size >= queue_size_limit:
                logging.info(
                    'local msg queue is above %d, sleep for consuming',
                    queue_size,
                )
                time.sleep(5)
                continue
            method_frame, header_frame, body = mqChannel.basic_get(mq_config_obj['queue_name'])
            if method_frame:
                global_message_buffer.put(body)
                mqChannel.basic_ack(method_frame.delivery_tag)
                message_count += 1
                if message_count % 1000 == 0:
                    logging.info(
                        'got %d messages by now',
                        message_count,
                    )
            else:
                logging.info(
                    'no message available from mq, sleep with %d message pulled',
                    message_count,
                )
                time.sleep(5)
            if (time.time() - start_time) >= timeout or global_is_stop:
                mqClient.clear()
                logging.info(
                    'it is time to quit message consumer'
                )
                break
        except Exception as e:
            if global_is_stop:
                break
            logging.error("in single process, consuming error: %s", e)
            time.sleep(6)
            continue

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
    parser.add_argument("mqConfig", type = str)
    parser.add_argument("resultDir", type = str)
    parser.add_argument("-ntmc", '--num_threads_mc', type = int, default = 5) # finterprinting interval in hours
    parser.add_argument("-ntfp", '--num_threads_fp', type = int, default = 5) # finterprinting interval in hours
    parser.add_argument('-to', '--timeout', type=float, default=80000)
    options = parser.parse_args()
    mqConfigFile = options.mqConfig
    resultDir = options.resultDir
    if not os.path.exists(resultDir):
        os.makedirs(resultDir)
    initLogging(resultDir)
    thread_num_mc = options.num_threads_mc
    thread_num_fp = options.num_threads_fp
    msg_worker_list = []
    for i in range(thread_num_mc):
        worker = threading.Thread(
            target=message_consumer,
            args=(
                mqConfigFile, 
                options.timeout,
            ),
        )
        msg_worker_list.append(worker)
    logging.info(
        'set up %d workers to consume messages from mq',
        len(msg_worker_list),
    )
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
    for worker in msg_worker_list:
        worker.start()
    for worker in ofp_worker_list:
        worker.start()
    start_time = time.time()
    while True:
        if options.timeout and (time.time()  - start_time) >= options.timeout:
            global_is_stop = True
            logging.info('it is time to quit')
            break
        else:
            time.sleep(5)
    global_is_stop = True
    result_dump_thread.join()
    for worker in msg_worker_list:
        worker.join()
    for worker in ofp_worker_list:
        worker.join()
    logging.info('globally exit')
