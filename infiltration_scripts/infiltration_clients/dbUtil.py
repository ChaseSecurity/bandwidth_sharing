#!/usr/bin/python
import pymysql

class DbClient(object):
    def __init__(self, host, port, user, passwd, database):
        self.host = host
        self.port = port
        self.user = user
        self.passwd = passwd
        self.conn = None
        self.cursor = None
        self.db = database

    def initNewConn(self):
        print(self.passwd)
        self.conn = pymysql.connect(
                host = self.host,
                port = self.port, 
                db = self.db,
                user = self.user,
                password = self.passwd,
                charset = "utf8mb4",
                autocommit = True, #avoid cache
                cursorclass = pymysql.cursors.DictCursor)

        return self.conn

    def closeConn(self):
        self.conn.close()

    def clear(self):
        if self.conn is not None:
            self.conn.close()

    def query(self, sqlStr):
        with self.conn.cursor() as currCursor:
            currCursor.execute(sqlStr)
            result = currCursor.fetchall()
            return result

    def queryExistRip(self, id):
        #if type(id) is str:
        #    sqlStr = "select * from rip where id = '{}'".format(id)
        #else:
        #    sqlStr = "select * from rip where id = {}".format(id)
        sqlStr = "select * from rip where id = '{}'".format(id)
        #import sys
        #sys.exit(1)
        with self.conn.cursor() as currCursor:
            resultStatus = currCursor.execute(sqlStr)
            result = currCursor.fetchall()
            if len(result) <= 0:
                return None
            firstItem = result[0]
            return firstItem

    def updateRip(self, id, captureTime, fpQueueTime, alQueueTime, requestCount):
        sqlStr = "update rip set lastCaptureTime = {},  lastFpQueueTime = {}, lastAlQueueTime = {}, captureCount = {} where id = '{}'".format(captureTime, fpQueueTime, alQueueTime, requestCount, id)
        with self.conn.cursor() as currCursor:
            resultStatus = currCursor.execute(sqlStr)
            self.conn.commit()
            return True if resultStatus == 1 else False

    def insertRip(self, id, captureTime, ip, fpQueueTime = -1, alQueueTime = -1):
        sqlStr = "insert into rip(id, startCaptureTime, lastCaptureTime, lastFpQueueTime, lastAlQueueTime,captureCount, ip) values('{0}', {1}, {1}, {2}, {3}, {4}, '{5}')".format(id, captureTime, fpQueueTime, alQueueTime, 1, ip)
        print(sqlStr)
        with self.conn.cursor() as currCursor:
            resultStatus = currCursor.execute(sqlStr)
            self.conn.commit()
            return True if resultStatus >= 1 else False



if __name__ == "__main__":
    import time
    import sys
    host = "192.239.50.6"
    port = 3306
    user = "worker"
    passwd = "acbc32853187"
    db = "residential"
    dbClient = DbClient(host, port, user, passwd, db)
    dbClient.initNewConn()
    #testSql = "select * from rip"
    #print(dbClient.query(testSql))
    #sys.exit(1)
    ip = "127.0.0.2"
    source = -1
    record = dbClient.queryExistRip(ip)
    if record is None:
        startTime = time.time()
        dbClient.insertRip(ip, startTime, source, ip)
    record = dbClient.queryExistRip(ip)
    print(record)
    count = record["count"]
    latestTime = time.time()
    dbClient.updateRip(ip, latestTime, count + 1)

    record = dbClient.queryExistRip(ip)
    print(record)
