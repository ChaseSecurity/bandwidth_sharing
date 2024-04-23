import socket
import ssl
import time
import logging

http_req='GET  / HTTP/1.1\r\nHost: ss\r\n\r\n'
telnet_req='\r\n'
ftp_req='\r\n'
ssh_req='SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1.4\r\n'
rtsp_req="DESCRIBE rtsp://ss:554 RTSP/1.0\r\nCSeq: 2\r\nUser-Agent: LibVLC\r\n\r\n"


# HTTP: tcp_req(ip,80,http_req)
# FTP: tcp_req(ip,21,ftp_req)
# TELNET: tcp_req(ip,23,telnet_req)
# SSH: tcp_req(ip,22,ssh_req)

TIMEOUT=2

def https_req(ip,port,req):
    if type(req) is str:
        req = req.encode('UTF-8')
    address=(ip,port)
    conn = socket.create_connection(address, timeout=TIMEOUT)
    conn = ssl.wrap_socket(conn)
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    conn.send(req)

    info=[]
    while 1:
        try:
            data=conn.recv(2048)
        except:
            break
        info.append(data)
        if not data:
            break 
    conn.close()
    return  b''.join(info)

def tcp_req(ip,port,req):
    if type(req) is str:
        req = req.encode('UTF-8')
    is_ipv6 = ':' in ip
    if is_ipv6:
        address = (ip, port, 0, 0)  
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    else:
        address = (ip, port)  
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    s.connect(address)
    s.send(req)
    data=s.recv(2048)  
    s.close()
    return data

def httpp_req(ip,port,req):
    if type(req) is str:
        req = req.encode('UTF-8')
    is_ipv6 = ':' in ip
    if is_ipv6:
        address = (ip, port, 0, 0)  
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    else:
        address = (ip, port)  
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    s.connect(address)
    s.send(req)
    info=[]
    while 1:
        try:
            data=s.recv(2048)
        except:
            break
        info.append(data)
        if not data:
            break 
    s.close()
    return b''.join(info)

def banner_grab(host, port, protocol):
    try:
        if protocol=="http":
            banner = httpp_req(host,port,http_req.replace("ss",host))
        if protocol=="ftp":
            banner = tcp_req(host,21,ftp_req)
        if protocol=="telnet":
            banner = tcp_req(host,23,telnet_req)
        if protocol=="ssh":
            banner = tcp_req(host,22,ssh_req)
        if protocol =="https":
            banner = https_req(host,443,http_req.replace("ss",host))
        if protocol =="rtsp":
            banner = tcp_req(host,554,rtsp_req.replace("ss",host))
    except ConnectionRefusedError as e:
        # logging.info(
        #     'exception during banner grabbing [%s:%s]: %s: %s',
        #     host,
        #     port,
        #     e,
        #     type(e),
        # )
        banner =  'Exception: Connection Refuse Error'
    except socket.timeout as e:
        banner =  'Exception: Connection Timeout'
    except Exception as e:
        logging.warning(
            'exception during banner grabbing [%s:%s]: %s: %s',
            host,
            port,
            e,
            type(e),
        )
        banner =  'Exception: Unknown Error'
    if type(banner) is bytes:
        banner = banner.decode('utf-8', 'backslashreplace')
    return banner

def banner_grab_batch(host):
    protocol_port_list = [
        ('tcp', 'http', 80),
        ('tcp', 'https', 443),
        ('tcp', 'ssh', 22),
        ('tcp', 'ftp', 21),
        ('tcp', 'telnet',23),
        ('tcp', 'rtsp', 554),
    ]
    result_list = []
    for transport, service, port in protocol_port_list:
        start_time = time.time()
        try:
            banner = banner_grab(host, port, service)
        except Exception as e:
            logging.warning(
                'error when grabbing banner: %s',
                e,
            )
            banner = 'Exception: {}'.format(e)
        end_time = time.time()
        is_response = False if banner.startswith('Exception:') else True
        result_item = {
            'banner': banner,
            'transport': transport,
            'port': port,
            'service': service,
            'banner_start_time': start_time,
            'banner_end_time': end_time,
            'is_response': is_response,
        }
        result_list.append(result_item)
    return result_list


'''
{"ip": "49.35.8.48", "id": "f44ea737-f753-471f-a367-04d7cceb7a49", "timestamp": 1506957618.45355, "port_list": [{"banner": "Connect Error", "type": "tcp", "port": "80", "service": {"type": "http"}}, {"banner": "Connect Error", "type": "tcp", "port": "21", "service": {"type": "ftp"}}, {"banner": "Connect Error", "type": "tcp", "port": "22", "service": {"type": "ssh"}}, {"banner": "Connect Error", "type": "tcp", "port": "23", "service": {"type": "telnet"}}, {"banner": "Connect Error", "type": "tcp", "port": "443", "service": {"type": "https"}}]}
'''

if __name__ == "__main__":
    # print tcp_req("101.228.62.178",554,rtsp_req.replace("ss","101.228.62.178"))
    # print banner_grab("23.39.32.86",443,"https")
    # print(banner_grab("84.85.9.238",23,"telnet"))
    # print(banner_grab("84.85.9.238",80,"http"))
    import sys
    ip = sys.argv[1]
    result = banner_grab_batch(ip)
    print(result)
