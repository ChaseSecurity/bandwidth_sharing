#/usr/bin/env python
import requests
import os,sys,re, traceback, codecs
import threading
from threading import Thread
import argparse
import json
import logging
import time
import random
import uuid #generate x-request-id header
import hmac, hashlib #generate and verify message authentication code
import cryptoUtil as cu
import mqUtil
from yaml import load, dump
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper
import infiltration_util as iu
import queue

global_result_queue = queue.Queue()
global_is_stop = False

def weighted_choice(
    items,
    weights=None,
):
    """ Provide weighted random choices
    """
    if weights is None:
        weights = [ 1 for item in items]
    weight_sum = sum(weights)
    choice = random.uniform(0, weight_sum)
    up_range = 0
    for item, weight in zip(items, weights):
        up_range += weight
        if choice <= up_range:
            return item
    return None

class GlobalConfig(object):
    """ Configuration parameters shared across threads
    """
    def __init__(self):
        self.is_ipv6 = False # if considering IPv6
        self.is_https = False
        self.num_threads = 30
        self.timeout = 86400
        self.result_dir = None
        self.proxy_providers = {}
        self.proxy_provider_weight_dict = {}
        self.proxies = {}
        self.proxy_weight_dict = {}
        self.proxy_last_use_dict = {}
        self.server_shared_key = None
        self.server_aes_key = None
        self.servers = []
        self.is_result_mq = True
        self.result_mqs = []
        self.result_dir = None


def dump_results(
    gc,
    interval=5,
    buffer_limit=20,
):
    ''' This function is used to dump results to the following outputs
            1. local file system
            2. message queues
    '''
    global global_result_queue
    global global_is_stop
    result_count = 0
    dump_start_time = time.time()
    result_buffers = []
    is_result_mq = gc.is_result_mq
    result_mq = None
    result_mq_client = None
    if is_result_mq:
        result_mq = gc.result_mqs[0]
        mq_retry_limit = 3
        retry_count = 0
        while retry_count < mq_retry_limit:
            try:
                result_mq_client = mqUtil.MqClient(
                    host=result_mq.host,
                    port=result_mq.port,
                    user=result_mq.user,
                    passwd=result_mq.passwd,
                    virtualHost=result_mq.virtual_host,
                    heartbeat=result_mq.heartbeat,
                )
                result_mq_client.initNewConn()
                result_mq_client.initNewChannel()
                ############ init queue
                queueList = ["testHeaderQueue"]
                result_mq_client.initExchangeAndQueue(queueList,
                    exchange=result_mq.exchange,
                    exchangeType=result_mq.exchange_type,
                )##############
                logging.info('connected to result mq server')
                break
            except Exception as e:
                result_mq_client = None
                retry_count += 1
                logging.warning(
                    'fail to connect to result mq server with exception %s',
                    e,
                )
                continue
    result_fd = None
    if gc.is_result_file:
        result_file = os.path.join(
            gc.result_dir,
            gc.result_file_name,
        )
        result_fd = open(result_file, 'a')
    is_quit = False
    try:
        while True:
            try:
                if result_count != 0 and result_count % 1000 == 0:
                    logging.info(
                        'finish %d infiltration attempts with %d seconds',
                        result_count,
                        time.time() - dump_start_time,
                    )
                is_empty = global_result_queue.empty()
                if is_empty and global_is_stop:
                    time.sleep(interval)
                    is_empty = global_result_queue.empty()
                    if is_empty and global_is_stop:
                        logging.info('quit result dumping thread')
                        is_quit = True
                if not is_empty:
                    result_item = global_result_queue.get_nowait()
                    result_count += 1
                    result_buffers.append(result_item)
                if (is_quit and len(result_buffers) > 0) or len(result_buffers) >= buffer_limit:
                    if result_mq_client:
                        result_buffer_str = json.dumps(result_buffers)
                        result_mq_client.publishMsg(
                            msg=result_buffer_str,
                            routingKey=result_mq.routing_key,
                            exchange=result_mq.exchange,
                            exchangeType=result_mq.exchange_type,
                        )
                    if result_fd:
                        for result_item in result_buffers:
                            result_fd.write(json.dumps(result_item) + '\n')
                            result_fd.flush()
                    result_buffers = []
                if is_quit:
                    break
                elif global_result_queue.empty():
                    time.sleep(interval)
                    continue
            except Exception as e:
                logging.warning('dumping error: %s, %s', e, traceback.format_exc())
                time.sleep(interval)
                continue
    except Exception as e:
        logging.warning('got error when dumping results: %s', e)
    finally:
        if result_fd:
            result_fd.close()
        if result_mq_client:
            result_mq_client.clear()
        logging.info('quit result dump with %d dumps', result_count)

class CollectThread(Thread):
    def __init__(
        self,
        global_config,
        request_timeout=(60, 60),
    ):
        self.gc = global_config
        self.timeout = self.gc.timeout
        self.request_timeout = request_timeout
        super(CollectThread, self).__init__()

    def run(self):
        run_start_time = time.time()
        global global_result_queue
        proxy_provider_ids = []
        proxy_provider_weights = []
        for pp_id in self.gc.proxy_providers:
            pp_weight = self.gc.proxy_provider_weight_dict[pp_id]
            proxy_provider_ids.append(pp_id)
            proxy_provider_weights.append(pp_weight)
        while True:
            try:
                if (time.time() - run_start_time) > self.gc.timeout:
                    logging.info('it is time to quit')
                    break
                # select server
                server_obj = weighted_choice(gc.servers)
                server_host = server_obj['host']
                # select proxy
                while True:
                    selected_proxy_provider_id = weighted_choice(
                        items=proxy_provider_ids,
                        weights=proxy_provider_weights,
                    )
                    selected_proxy_provider = self.gc.proxy_providers[selected_proxy_provider_id]
                    selected_proxy_obj = weighted_choice(
                        selected_proxy_provider.get_proxies()
                    )
                    selected_proxy_id = selected_proxy_obj.get_proxy_id()
                    if selected_proxy_obj.is_sticky:
                        last_use_time = self.gc.proxy_last_use_dict.get(selected_proxy_id, 0)
                        sticky_time = selected_proxy_obj.sticky_time
                        # skip proxies which are sticky and used recently
                        if (time.time() - last_use_time) < sticky_time:
                            time.sleep(1) # sleep before next selection
                            continue
                    break
                click_type = selected_proxy_provider.tag
                is_sticky_proxy = selected_proxy_obj.is_sticky
                proxies = selected_proxy_obj.get_requests_proxy_config()
                # if set up is_ipv6 as true,
                # we will request a domain that has both ipv6/ipv4 addresses
                if self.gc.is_ipv6:
                    server_host = 'ipv6.' + server_host
                if self.gc.is_https:
                    schema = 'https'
                else:
                    schema = 'http'
                requestTime = time.time()
                xRequestId = str(uuid.uuid4())
                #print(urlComponents)
                subDomainName = "{}-{:0>2}-{}".format(xRequestId.split("-")[0], click_type, int(requestTime))
                url = "{}://{}.{}".format(schema, subDomainName, server_host)
                #url = "{}://{}".format(schema, server_host)
                if is_sticky_proxy:
                    url = "{}/aesclick{}s/{}".format(url, click_type, xRequestId)
                else:
                    url = "{}/aesclick{}/{}".format(url, click_type, xRequestId)
                headers = {
                  "x-request-id" : xRequestId,
                }
                #url = "https://ipv4.icanhazip.com"
                response = requests.get(
                    url,
                    headers=headers,
                    proxies=proxies,
                    timeout=self.request_timeout,
                    #auth=auth,
                )
                if click_type == 1:
                    response_text = response.text.replace('<html><head></head><body>', '')
                    response_text = response_text.replace('</body></html>', '')
                else:
                    response_text = response.text
                headerDump = json.dumps(dict(response.headers))
                if response.status_code != 200:
                    logging.error(
                        "error for {} with non-200 http response: {}, and headers {}, \
                                and proxies {}, and click type {}".format(
                            url,
                            response.status_code,
                            headerDump,
                            proxies,
                            click_type,
                        )
                    )
                    continue
                endTime = time.time()
                #print("response.text", response.text.encode("hex"))
                #print(response.encoding)
                #print('response.headers', response.headers, '\n')
                #print('response_text', response_text, '\n')
                clearResponse = cu.decryptAES_CBCMsg(self.gc.server_aes_key, response_text)
                if type(clearResponse) is bytes:
                    clearResponse = clearResponse.decode('utf-8')
                #print('clearResponse', clearResponse)
                responseObj = json.loads(clearResponse)
                payloadStr = responseObj["payload"]
                oldMacStr = responseObj["identity"]
                hmacObj = hmac.new(
                    #bytes.fromhex(self.gc.server_shared_key),
                    self.gc.server_shared_key.encode('UTF-8'),
                    payloadStr.encode('UTF-8'),
                    hashlib.sha256,
                )
                newMacStr = hmacObj.hexdigest()
                #print("receivedMac: {0}, calculatedMac: {1}".format(oldMacStr, newMacStr))
                if newMacStr.lower() != oldMacStr:
                    logging.error(
                        "mac doesn't consistent, potential data manipulation for request %s, proxy %s",
                        url,
                        proxies,
                    )
                    #print(newMacStr, oldMacStr)
                    #print(payloadStr, type(payloadStr))
                    #print(self.gc.server_shared_key)
                    #sys.exit(1)
                    continue
                payload = json.loads(payloadStr)
                payload["xRequestId"] = xRequestId
                payload["id"] = xRequestId
                payload["startTime"] = requestTime
                payload["timestamp"] = requestTime
                payload["endTime"] = endTime
                payload["url"] = url
                payload["source"] = click_type
                payload["responseHeader"] = headerDump # measure potential header modification
                payload['proxies'] = proxies
                payload['is_sticky_proxy'] = is_sticky_proxy
                #publish partial payload to mq
                #publish2Mq(payload)
                global_result_queue.put(payload)
                # set the last time when this proxy is used
                self.gc.proxy_last_use_dict[selected_proxy_id] = requestTime
            except Exception as e:
                try:
                    logging.warning(
                        'exception when collecting proxy nodes: %s, %s',
                        e,
                        traceback.format_exc(),
                    )
                    time.sleep(6)
                except Exception as e:
                    time.sleep(30)

def parse_infiltration_config(config_file):
    gc = GlobalConfig()
    config_dir = os.path.dirname(config_file)
    config_body = open(config_file, 'r').read()
    config_dict = load(config_body, Loader)
    gc.is_ipv6 = config_dict.get('is_ipv6', False)
    gc.is_https = config_dict.get('is_https', False)
    gc.num_threads = config_dict.get('num_threads', 30)
    gc.timeout = config_dict.get('timeout', 86400)
    gc.result_dir = config_dict['result_dir']
    gc.is_result_file = config_dict.get('is_result_file', False)
    gc.result_file_name = config_dict.get('result_file_name', None)
    provider_config_list = config_dict.get('proxy_providers', [])
    for provider_config in provider_config_list:
        # p_name = provider_config['name']
        p_tag = provider_config['tag']
        p_weight = provider_config['weight']
        p_config_file = provider_config['cfg']
        if not p_config_file.startswith('/'):
            p_config_file = os.path.join(config_dir, p_config_file)
        proxy_provider = iu.ProxyProvider.init_from_config(p_config_file)
        p_id = proxy_provider.id
        proxy_provider.tag = p_tag
        gc.proxy_providers[p_id] = proxy_provider
        gc.proxy_provider_weight_dict[p_id] = p_weight
        proxy_list = proxy_provider.get_proxies()
        single_proxy_weight = p_weight / float(len(proxy_list))
        for proxy_obj in proxy_list:
            proxy_id = proxy_obj.get_proxy_id()
            gc.proxies[proxy_id] = proxy_obj
            gc.proxy_weight_dict[proxy_id] = single_proxy_weight
    logging.info(
        'got %d proxy providers, %d proxies',
        len(gc.proxy_providers),
        len(gc.proxies),
    )
    gc.server_aes_key = config_dict.get('server_aes_key', None)
    gc.server_shared_key = config_dict.get('server_shared_key', None)
    for server_config in config_dict.get('server_list', []):
        gc.servers.append(server_config)
    logging.info(
        'got %d servers',
        len(gc.servers),
    )
    gc.is_result_mq = config_dict.get('is_result_mq', False)
    for mq_config in config_dict.get('result_mqs', []):
        mqc_obj = iu.MqConfig.load_from_dict(mq_config)
        gc.result_mqs.append(mqc_obj)
    logging.info(
        'got %d result mq servers',
        len(gc.result_mqs),
    )
    gc.result_dir = config_dict['result_dir']
    if not os.path.exists(gc.result_dir):
        os.makedirs(gc.result_dir)
    return gc

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('config_file', type=str)
    parser.add_argument('-to', '--timeout',  type=float, default=None)
    parser.add_argument('-nt', '--num_threads',  type=int, default=None)
    parser.add_argument("-rd", '--result_dir',  type=str, default=None)
    options = parser.parse_args()
    config_file = options.config_file
    #parse config file
    gc = parse_infiltration_config(config_file)
    if options.timeout is not None:
        gc.timeout = options.timeout
    if options.num_threads is not None:
        gc.num_threads = options.num_threads
    if options.result_dir is not None:
        gc.result_dir = options.result_dir
    #print('gc config is {}'.format(gc.__dict__))
    #print('gc mq config is {}'.format(gc.result_mqs[0].__dict__))
    result_dir = gc.result_dir
    if not os.path.exists(result_dir):
      os.makedirs(result_dir)
    log_file = os.path.join(result_dir, "logs")
    #print(log_file)
    #initialize logging
    loggingFormat = "%(levelname)s-%(name)s-%(asctime)s-<%(message)s>-%(threadName)s-%(processName)s-%(lineno)d-%(filename)s"
    formatter = logging.Formatter(loggingFormat)
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(logging.DEBUG)
    stream_handler.setFormatter(formatter)
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.WARNING)
    logger = logging.getLogger("")
    logger.setLevel(logging.INFO)
    logger.addHandler(stream_handler)
    logger.addHandler(file_handler)
    #logging.basicConfig(level = logging.DEBUG, format = loggingFormat^
    #print("start infiltration")
    logger.info("start infiltration")

    worker_list = []
    for i in range(gc.num_threads):
      thread = CollectThread(
          global_config=gc,
      )
      worker_list.append(thread)
    dump_thread = Thread(
        target=dump_results,
        args=(
            gc,
        ),
        kwargs=dict(
            buffer_limit=20,
            interval=5,
        ),
    )
    dump_thread.start()
    for worker in worker_list:
      worker.start()
    for worker in worker_list:
      worker.join()
    global_is_stop = True
    dump_thread.join()
    logging.info(
        'the infiltration is done'
    )
