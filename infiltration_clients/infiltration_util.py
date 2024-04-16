""" This file defines classes and functions to facilitate infiltration process
    1. ProxyProvider
    2. Proxy
"""
import os, sys
import logging
import traceback
from yaml import load, dump
import string
import random
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper


class ProxyType(object):
    HTTP = 1
    HTTPS = 2
    SOCKS4 = 4
    SOCKS5 = 8


class Proxy(object):
    def __init__(
        self,
        host,
        port,
        proxy_type,
        provider_id,
        user=None,
        passwd=None,
        is_sticky=False,
        sticky_time=60,
    ):
        self.host = host
        self.port = port
        self.provider_id = provider_id
        self.user = user
        self.passwd = passwd
        self.is_sticky = is_sticky
        self.sticky_time = sticky_time
    def get_random_str(self, str_len=6):
        return ''.join(
            random.sample(string.ascii_uppercase + string.digits, str_len)
        )
    def get_proxy_id(self):
        return '{host}:{port}:{sticky}:{provider_id}'.format(
            host=self.host,
            port=self.port,
            sticky='sticky' if self.is_sticky else 'non-sticky',
            provider_id=self.provider_id,
        )
    def get_requests_proxy_config(self):
        if self.user is not None:
            auth = '{user}:{passwd}@'.format(
                user=self.user,
                passwd=self.passwd,
            )
        else:
            auth = ''
        proxy = 'http://{auth}{host}:{port}'.format(
            auth=auth,
            host=self.host,
            port=self.port,
        )
        return {
            'https': proxy,
            'http' : proxy,
        }

class LuminatiProxy(Proxy):
    def __init__(
        self,
        host,
        port,
        proxy_type,
        provider_id,
        user=None,
        passwd=None,
        is_sticky=False,
        sticky_time=60,
    ):
        self.host = host
        self.port = port
        self.provider_id = provider_id
        self.user = user
        self.passwd = passwd
        self.is_sticky = is_sticky
        self.sticky_time = sticky_time
    def get_requests_proxy_config(self):
        if self.user is not None and self.is_sticky:
            auth = '{user}:{passwd}@'.format(
                user=self.user + '-session-' + self.get_random_str(),
                passwd=self.passwd,
            )
        elif self.user is not None:
            auth = '{user}:{passwd}@'.format(
                user=self.user,
                passwd=self.passwd,
            )
        else:
            auth = ''
        proxy = 'http://{auth}{host}:{port}'.format(
            auth=auth,
            host=self.host,
            port=self.port,
        )
        return {
            'https': proxy,
            'http' : proxy,
        }


class ProxyProvider(object):
    def __init__(
        self,
        id,
        name,
        proxy_list=None,
        tag=None,
    ):
        self.id = id
        self.name = name
        self.proxy_list = proxy_list if proxy_list is not None else []
        self.tag = tag if tag is not None else id

    @staticmethod
    def init_from_config(config_file):
        try:
            config_str = open(config_file, 'r').read()
            pp_config = load(config_str, Loader)
            id = pp_config['id']
            name = pp_config['name']
            default_user = pp_config.get('user', None)
            default_passwd = pp_config.get('passwd', None)
            default_proxy_type = pp_config.get('proxy_type', None)
            default_is_sticky = pp_config.get('is_sticky', None)
            proxy_file_list = pp_config['proxies']
            proxy_list = []
            config_dir = os.path.dirname(config_file)
            for proxy_file in proxy_file_list:
                file_path = proxy_file['file']
                file_path = os.path.join(
                    config_dir,
                    file_path,
                )
                curr_user = proxy_file.get('user', None)
                curr_passwd = proxy_file.get('passwd', None)
                curr_proxy_type = proxy_file.get('proxy_type', None)
                curr_is_sticky = proxy_file.get('is_sticky', None)
                curr_user = default_user if curr_user is None else curr_user
                curr_passwd = default_passwd if curr_passwd is None else curr_passwd
                curr_proxy_type = default_proxy_type if curr_proxy_type is None else curr_proxy_type
                curr_is_sticky = default_is_sticky if curr_is_sticky is None else curr_is_sticky
                sep = proxy_file.get('sep', ',')
                if (curr_proxy_type is None or curr_is_sticky is None):
                    logging.error(
                        'required fields of is_sticky and proxy_type were not found for file %s',
                        file_path,
                    )
                    return None
                curr_proxy_type_int = 0
                for proxy_type in curr_proxy_type.split('|'):
                    if proxy_type.lower().strip() == 'http':
                        curr_proxy_type_int |= ProxyType.HTTP
                    elif proxy_type.lower().strip() == 'https':
                        curr_proxy_type_int |= ProxyType.HTTPS
                    elif proxy_type.lower().strip() == 'socks4':
                        curr_proxy_type_int |= ProxyType.SOCKS4
                    elif proxy_type.lower().strip() == 'socks5':
                        curr_proxy_type_int |= ProxyType.SOCKS5
                with open(file_path, 'r') as fd:
                    for line in fd:
                        line = line.strip()
                        if line.startswith('#'):
                            continue
                        attrs = line.split(sep)
                        host = attrs[0]
                        port = attrs[1]
                        if len(attrs) > 2 and curr_is_sticky:
                            sticky_time = float(attrs[2])
                        else:
                            sticky_time = 0
                        if id == 'smartproxy.com':
                            curr_proxy = SmartProxyProxy(
                                host=host,
                                port=port,
                                proxy_type=curr_proxy_type_int,
                                provider_id=id,
                                user=curr_user,
                                passwd=curr_passwd,
                                is_sticky=curr_is_sticky,
                                sticky_time=sticky_time,
                            )
                        elif id == 'luminati.io' or id == 'luminati.io_dc':
                            curr_proxy = LuminatiProxy(
                                host=host,
                                port=port,
                                proxy_type=curr_proxy_type_int,
                                provider_id=id,
                                user=curr_user,
                                passwd=curr_passwd,
                                is_sticky=curr_is_sticky,
                                sticky_time=sticky_time,
                            )
                        elif id == 'luminati.io_resi' or id == 'luminati.io_mobile':
                            curr_proxy = LuminatiProxy(
                                host=host,
                                port=port,
                                proxy_type=curr_proxy_type_int,
                                provider_id=id,
                                user=curr_user,
                                passwd=curr_passwd,
                                is_sticky=curr_is_sticky,
                                sticky_time=sticky_time,
                            )
                        elif id == 'oxylabs.io':
                            curr_proxy = OxylabsProxy(
                                host=host,
                                port=port,
                                proxy_type=curr_proxy_type_int,
                                provider_id=id,
                                user=curr_user,
                                passwd=curr_passwd,
                                is_sticky=curr_is_sticky,
                                sticky_time=sticky_time,
                            )
                        else:
                            curr_proxy = Proxy(
                                host=host,
                                port=port,
                                proxy_type=curr_proxy_type_int,
                                provider_id=id,
                                user=curr_user,
                                passwd=curr_passwd,
                                is_sticky=curr_is_sticky,
                                sticky_time=sticky_time,
                            )
                        proxy_list.append(curr_proxy)
            logging.info(
                'proxy provider %s, %s, with %d proxies',
                id,
                name,
                len(proxy_list),
            )
            proxy_provider = ProxyProvider(
                id=id,
                name=name,
                proxy_list=proxy_list,
            )
            return proxy_provider
        except Exception as e:
            logging.error(
                'error when parsing config file %s: %s',
                config_file,
                traceback.format_exc(),
            )
            return None

    def get_proxies(
        self,
        is_sticky=None,
        proxy_type=None,
        min_sticky_time=-1,
        max_sticky_time=-1,
    ):
        result_list = []
        for proxy_obj in self.proxy_list:
            if is_sticky and proxy_obj.is_sticky != is_sticky:
                continue
            if proxy_type and proxy_type >  proxy_obj.proxy_type:
                continue
            if min_sticky_time != -1 and proxy_obj.sticky_time < min_sticky_time:
                continue
            if max_sticky_time != -1 and proxy_obj.sticky_time > max_sticky_time:
                continue
            result_list.append(proxy_obj)
        return result_list


class MqConfig(object):
    def __init__(
        self,
        host=None,
        port=None,
        user=None,
        passwd=None,
        routing_key=None,
        exchange=None,
        exchange_type=None,
        virtual_host=None,
        queue_limit=50,
        heartbeat=1800,
    ):
        self.host = host
        self.port = port
        self.user = user
        self.passwd = passwd
        self.routing_key = routing_key
        self.exchange = exchange
        self.exchange_type = exchange_type
        self.virtual_host = virtual_host
        self.queue_limit = queue_limit
        self.heartbeat = heartbeat

    @staticmethod
    def load_from_dict(config_dict):
        mqc_obj = MqConfig()
        mqc_obj.host = config_dict.get('host', None)
        mqc_obj.port = config_dict.get('port', None)
        mqc_obj.user = config_dict.get('user', None)
        mqc_obj.passwd = config_dict.get('passwd', None)
        mqc_obj.routing_key = config_dict.get('routing_key', None)
        mqc_obj.exchange = config_dict.get('exchange', None)
        mqc_obj.exchange_type = config_dict.get('exchange_type', None)
        mqc_obj.virtual_host = config_dict.get('virtual_host', None)
        mqc_obj.queue_limit = config_dict.get('queue_limit', None)
        mqc_obj.heartbeat = config_dict.get('heartbeat', 60)
        return mqc_obj
