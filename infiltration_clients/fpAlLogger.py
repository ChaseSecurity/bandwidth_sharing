#!/usr/bin/python
#read msg from backup queues of al/fp requests, write to files for different dates
import argparse
import os,sys
import dbUtil
import mqUtil
import json
import logging
import time
import multiprocessing as mp
import datetime
import traceback

receiveCount = 0
receiveLimit = 100000
dbObj = None
mqObj = None
consumerQueue = "backupQueue"
errorMsgList = None

overallStartTime = time.time()
#callbach functions to consume messages from request queue
def mqConsumerCallback(ch, method, properties, body):
    global receiveCount
    global receiveLimit
    global mqClient
    global errorMsgList
    global resultDir

    msgList = None
    try:
        msgList = json.loads(body) #should be a list of msgs
        if errorMsgList is not None:
            msgList.extend(errorMsgList)

        receiveCount += len(msgList)
        if len(msgList) != 0:
            startTimeStamp = msgList[0]["timestamp"]
            currDateStr = datetime.datetime.utcfromtimestamp(startTimeStamp).strftime("%Y%m%d")
            currFileName = "taskList_{}_{}.txt".format(currDateStr, mp.current_process().name)
            with open(os.path.join(resultDir, currFileName), "a") as fd:
                for msg in msgList:
                    msgStr = json.dumps(msg)
                    fd.write(msgStr + "\n")
                fd.flush
        ch.basic_ack(delivery_tag = method.delivery_tag, multiple = True)
    except Exception as e:
        logging.error("inside consuming callback: %s", traceback.format_exc())
        errorMsgList = msgList

def createMqObj(mqConfigFile):
    global mqClient
    with open(mqConfigFile, "r") as fd:
        for line in fd:
            if line.startswith("#"):
                continue
            attrs = line.strip().split(",")
            host = attrs[0]
            port   = int(attrs[1])
            user = attrs[2]
            passwd = attrs[3]
            if len(attrs) >= 5:
                vhost = attrs[4]
            else:
                vhost = "/"
            mqClient = mqUtil.MqClient(host = host, port = port, user = user, passwd = passwd, virtualHost = vhost)
            logging.info("new mq obj created")
            return mqClient

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

def singleProcess(params):
    global resultDir
    global mqClient
    global consumerQueue
    global mqConfigFile
    logger = initLogging(resultDir)
    while True:
        try:
            #init database and mq 
            mqClient = createMqObj(mqConfigFile)
            mqConn = mqClient.initNewConn()
            mqChannel = mqClient.initNewChannel()
            mqClient.consumeMsg(queueName = consumerQueue, consumeCallback = mqConsumerCallback, prefetchCount = 1000)
        except Exception as e:
            logging.error("in single process, consuming error: %s", e)
            continue

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    #parser.add_argument("dbConfig", type = str)
    parser.add_argument("mqConfig", type = str)
    parser.add_argument("resultDir", type = str)
    parser.add_argument("-pn", type = int, default = 1) # finterprinting interval in hours
    options = parser.parse_args()
    mqConfigFile = options.mqConfig
    resultDir = options.resultDir
    if not os.path.exists(resultDir):
        os.makedirs(resultDir)
    processNum = options.pn
    processList = []
    params = {
            }
    for i in range(processNum):
        label = "process_{}".format( i + 1)
        newProcess = mp.Process(target = singleProcess, args = (params, ), name = label)
        processList.append(newProcess)
    for process in processList:
        process.start()
    for process in processList:
        process.join()


