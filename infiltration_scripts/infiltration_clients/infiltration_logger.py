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

global_result_queue = Queue()
global_is_stop = False

def result_dump(
    result_file,
    interval=5,
):
    global global_result_queue
    global global_date_format
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
                logging.info(
                    'sleep to wait for result items, with %d dumped',
                    result_count,
                )
                time.sleep(interval)
                continue
            # get message and flush to local files
            result_json = global_result_queue.get_nowait()
            if type(result_json) is bytes:
                result_json = result_json.decode('utf-8')
            result_list = json.loads(result_json)
            for result_item in result_list:
                result_count += 1
                result_fd.write(json.dumps(result_item) + '\n')
            result_fd.flush()
        except Exception as e:
            logging.warning(
                'error when dumping results with exception %s and traceback %s',
                e,
                traceback.format_exc(),
            )
            time.sleep(interval)
            continue
    result_fd.close()
    logging.info('quit result dump with %d dump', result_count)

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

def msg_consumer(mq_config_file, timeout=80000):
    global global_result_queue
    global global_is_stop
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
            method_frame, header_frame, body = mqChannel.basic_get(mq_config_obj['queue_name'])
            if method_frame:
                global_result_queue.put(body)
                mqChannel.basic_ack(method_frame.delivery_tag)
                message_count += 1
                if message_count % 1000 == 0:
                    logging.info(
                        'got %d messages by now',
                        message_count,
                    )
            else:
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

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mqConfig", type = str)
    parser.add_argument("resultDir", type = str)
    parser.add_argument("-nt", '--num_threads', type = int, default = 5) # finterprinting interval in hours
    parser.add_argument('-to', '--timeout', type=float, default=80000)
    options = parser.parse_args()
    mqConfigFile = options.mqConfig
    resultDir = options.resultDir
    if not os.path.exists(resultDir):
        os.makedirs(resultDir)
    initLogging(resultDir)
    thread_num = options.num_threads
    worker_list = []
    for i in range(thread_num):
        worker = threading.Thread(
            target=msg_consumer,
            args=(
                mqConfigFile, 
                options.timeout,
            ),
        )
        worker_list.append(worker)
    logging.info(
        'set up %d workers to consume messages from mq',
        len(worker_list),
    )
    result_dump_thread = threading.Thread(
        target=result_dump,
        args=(
            os.path.join(
                resultDir,
                'infiltration_results.json',
            ),
        ),
        kwargs=dict(
            interval=5,
        ),
    )
    result_dump_thread.start()
    for worker in worker_list:
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
    for worker in worker_list:
        worker.join()
    logging.info('globally exit')
