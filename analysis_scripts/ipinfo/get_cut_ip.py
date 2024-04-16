from ast import arg
from asyncio.log import logger
from email import header
import requests
import time
import json
import logging
import argparse
import gc

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
logging.info("inited")

parser = argparse.ArgumentParser()
parser.add_argument('newDomainPath')
parser.add_argument('passiveDomainPath')
parser.add_argument('resultPath')
args = parser.parse_args()



def query_all_domain():
    ipSet = retrieve_domain(args.newDomainPath)
    query_domainSet(ipSet)


def query_new_domain():

    ipSet = rerieve_new_domain(
        args.newDomainPath, args.passiveDomainPath)
    
    logging.info(len(ipSet))


    all_old_ip_file=open('1_ip.txt','w')

    i=0
    dir=1
    ip_file=open(str(dir)+'/'+'ips.txt','w')
    for ip in ipSet:
        i+=1
        if i%50000==0:
            dir+=1
            ip_file.close()
            ip_file=open(str(dir)+'/'+'ips.txt','w')
        
        ip_file.write(ip+'\n')
        all_old_ip_file.write(ip+'\n')
    # query_domainSet(ipSet)



def retrieve_passive_domain(path,newDomainSet):
    
    with open(path, "r") as f:
        line = f.readline()
        while line:
            data = json.loads(line)
            newDomainSet.discard(data['ip'])
            line = f.readline()
            if((len(newDomainSet) % 100000) == 0) :
                logging.info(len(newDomainSet))
                gc.collect()
    logging.info(len(newDomainSet))
    f.close()
    return newDomainSet


def retrieve_domain(path):

    logging.info('start retrieve_domain')
    ipSet = set()
    with open(path, "r") as f:
        line = f.readline()
        while line:
            line = line.strip('\n')
            if line.split():
                ipSet.add(line)
            line = f.readline()
    f.close()
    logging.info(len(ipSet))
    gc.collect()
    return ipSet


def rerieve_new_domain(newDomainPath, passiveDomainPath):

    newDomainSet = retrieve_domain(newDomainPath)

    return retrieve_passive_domain(passiveDomainPath,newDomainSet)


def query_domainSet(ipSet):
    logging.info('start')
    logging.info(len(ipSet))
    requests.packages.urllib3.disable_warnings()
    requests.adapters.DEFAULT_RETRIES = 5
    with open(args.resultPath, 'a') as file:
        for ip in iter(ipSet):
            url = "https://ipinfo.io/"+ip+"?token=Anonymize"
            try:
                response = requests.get(url, verify=False)
                json_response = response.json()

            except Exception as e:
                logging.error(repr(e))
                continue
            if 'error' in json_response:
                logging.info(json_response)
                return

            json_response.update({'ip': ip})

            file.write(json.dumps(json_response)+'\n')

            logging.info(json_response['ip'] + ' Ipinfo is ok')

    file.close()


query_new_domain()
