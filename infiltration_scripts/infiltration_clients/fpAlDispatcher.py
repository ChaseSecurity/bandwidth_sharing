#!/usr/bin/python
import argparse
import os,sys
import dbUtil
import mqUtil
import json
import logging
import time
import multiprocessing as mp

receiveCount = 0
receiveLimit = 100000
dbObj = None
mqObj = None
aliveQueue = "aliveness"
fpQueue = "fingerprint"
backupQueue = "backupQueue"
fpExchange = "" # publish to alive queue and fpqueue
aliveExchange = "" # publish to alive queue and fpqueue
consumerQueue = "residentialRequest"
errorMsgList = None

class Request(object):
  def __init__(self, ip, id, timestamp, source):
      self.ip = ip
      self.id = id
      self.timestamp = timestamp
      self.source = source

overallStartTime = time.time()
#callbach functions to consume messages from request queue
def mqConsumerCallback(ch, method, properties, body):
    global receiveCount
    global receiveLimit
    global fpInterval
    global alInterval
    global dbClient
    global mqClient
    global errorMsgList
    #if receiveCount >= 1000:
    #    mqClient.clear()
    #    dbClient.clear()
    #    endTime = time.time()
    #    print("time cost is %d seconds", endTime - overallStartTime)
    #    sys.exit(1)

    #parse body
    msgList = None
    try:
        msgList = json.loads(body) #should be a list of msgs
        if errorMsgList is not None:
            msgList.extend(errorMsgList)

        receiveCount += len(msgList)
        logging.info("consume %d new message, No %d", len(msgList),  receiveCount)
        newMsgList = []
        for bodyObj in msgList:
            bodyMsg = json.dumps(bodyObj)
            id = bodyObj["id"]
            ip = bodyObj["ip"]
            captureTime = bodyObj["timestamp"]
            source = bodyObj["source"]
            #query the db for existence
            record = dbClient.queryExistRip(ip)
            isAlive = False
            isFP = False
            isNew = False
            currTime = time.time()
            if record is None:
                logging.info("capture a new IP: %s", bodyMsg)
                isAlive = True
                isFP = True
                isNew = True
                currCaptureTime = captureTime
                currFpQueueTime = currTime
                currAlQueueTime = currTime
                currFpCount = 1
                currAlCount = 1
                currCaptureCount = 1
                result = dbClient.insertRip(ip, currCaptureTime, ip, currFpQueueTime, currAlQueueTime)
                if result == False:
                    logging.error("DB Insert Error: failed to insert new records into dbfor message %s", body) 
            else:
                recordId = record["id"]
                lastAlQueueTime = record["lastAlQueueTime"]
                lastCaptureTime = record["lastCaptureTime"]
                lastFpQueueTime = record["lastFpQueueTime"]
                lastAlTime = record["lastAlTime"]
                lastFpTime = record["lastFpTime"]
                oldAlCount = record["alCount"]
                oldFpCount = record["fpCount"]
                oldCaptureCount = record["captureCount"]

                timePastForFP = currTime - lastFpQueueTime
                timePastForAl = currTime - lastAlQueueTime
                if timePastForFP >= fpInterval:
                    isFP = True
                if timePastForAl >= alInterval:
                    isAlive = True
                currCaptureTime = captureTime
                currFpQueueTime = currTime if isFP == True else lastFpQueueTime
                currAlQueueTime = currTime if isAlive == True else lastAlQueueTime
                currCaptureCount = oldCaptureCount + 1
                result = dbClient.updateRip(recordId, currCaptureTime, currFpQueueTime, currAlQueueTime, currCaptureCount)
                if result == False:
                    logging.error("DB Update Error: failed to insert new records into dbfor message %s", body) 

            bodyObj["isFP"] = False
            bodyObj["isAl"] = False
            if isFP:
                #sent to fp queue
                mqClient.publishMsg(bodyMsg, routingKey = fpQueue)
                bodyObj["isFP"] = True
            if isAlive:
                #sent to alive queue
                mqClient.publishMsg(bodyMsg, routingKey = aliveQueue)
                bodyObj["isAl"] = True
            newMsgList.append(bodyObj)
        mqClient.publishMsg(json.dumps(newMsgList), routingKey = backupQueue)
        ch.basic_ack(delivery_tag = method.delivery_tag, multiple = True)
    except Exception as e:
        logging.error("inside consuming callback: %s", e)
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

def createDbObj(dbConfigFile):
    global dbClient
    with open(dbConfigFile, "r") as fd:
        for line in fd:
            if line.startswith("#"):
                continue
            attrs = line.strip().split(",")
            host = attrs[0]
            port   = int(attrs[1])
            user = attrs[2]
            passwd = attrs[3]
            db = attrs[4]
            dbClient = dbUtil.DbClient(host, port, user, passwd, db)
            logging.info("new mq obj created")
            return dbClient

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
    global dbClient
    global consumerQueue
    global mqConfigFile
    global dbConfigFile
    logger = initLogging(resultDir)
    while True:
        try:
            #init database and mq 
            mqClient = createMqObj(mqConfigFile)
            dbClient = createDbObj(dbConfigFile)
            dbClient.initNewConn()
            mqConn = mqClient.initNewConn()
            mqChannel = mqClient.initNewChannel()
            mqClient.consumeMsg(queueName = consumerQueue, consumeCallback = mqConsumerCallback, prefetchCount = 1000)
        except Exception as e:
            logging.error("in single process, consuming error: %s", e)
            continue

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("dbConfig", type = str)
    parser.add_argument("mqConfig", type = str)
    parser.add_argument("resultDir", type = str)
    parser.add_argument("-pn", type = int, default = 2) # finterprinting interval in hours
    parser.add_argument("-fpi", type = int, default = 6) # finterprinting interval in hours
    parser.add_argument("-ali", type = int, default = 24) # aliveness interval in hours
    options = parser.parse_args()
    dbConfigFile = options.dbConfig
    mqConfigFile = options.mqConfig
    resultDir = options.resultDir
    if not os.path.exists(resultDir):
        os.makedirs(resultDir)
    fpInterval = options.fpi * 3600
    alInterval = options.ali * 3600
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


