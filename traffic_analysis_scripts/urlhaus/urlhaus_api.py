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
    domainSet = retrieve_domain(args.newDomainPath)
    query_domainSet(domainSet)


def query_new_domain():

    domainSet = rerieve_new_domain(
        args.newDomainPath, args.passiveDomainPath)
    
    logging.info(len(domainSet))
    
    query_domainSet(domainSet)



def retrieve_passive_domain(path,newDomainSet):
    
    with open(path, "r") as f:
        line = f.readline()
        while line:
            data = json.loads(line)
            newDomainSet.discard(data['domain'])
            line = f.readline()
            if((len(newDomainSet) % 100000) == 0) :
                logging.info(len(newDomainSet))
                gc.collect()
    logging.info(len(newDomainSet))
    f.close()
    return newDomainSet


def retrieve_domain(path):

    logging.info('start retrieve_domain')
    domainSet = set()
    with open(path, "r") as f:
        line = f.readline()
        while line:
            line = line.strip('\n')
            if line.split():
                domainSet.add(line)
            line = f.readline()
    f.close()
    logging.info(len(domainSet))
    gc.collect()
    return domainSet


def rerieve_new_domain(newDomainPath, passiveDomainPath):

    newDomainSet = retrieve_domain(newDomainPath)

    return retrieve_passive_domain(passiveDomainPath,newDomainSet)


def query_domainSet(domainSet):
    logging.info('start')
    logging.info(len(domainSet))
    requests.packages.urllib3.disable_warnings()
    requests.adapters.DEFAULT_RETRIES = 5
    with open(args.resultPath, 'a') as file:
        for domain in iter(domainSet):
            url = 'https://urlhaus-api.abuse.ch/v1/host/'
            try:
                
                response = requests.post(url, data={'host':domain}, timeout=15,verify=False)
                json_response = response.json()
                # print(response.text)
            except Exception as e:
                logging.error(repr(e))
                


            json_response.update({'domain': domain})

            file.write(json.dumps(json_response)+'\n')
            logging.info(json_response['domain'] + ' urlhaus is ok')

    file.close()


query_new_domain()
