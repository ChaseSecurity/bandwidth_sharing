#!/usr/bin/python
import pika
import logging

#mqclient
class MqClient(object):
    def __init__(self, host, port, user, passwd, virtualHost = "/", heartbeat = 300):
        self.host = host
        self.port = port
        self.user = user
        self.passwd = passwd
        self.virtualHost = virtualHost
        self.credentials = pika.PlainCredentials(self.user, self.passwd)
        self.connParameters = pika.ConnectionParameters(credentials = self.credentials, host = self.host, port = self.port, virtual_host = self.virtualHost, heartbeat = heartbeat)
        self.conn = None
        self.channel = None
        self.receiveCount = 0

    def initNewConn(self, isSSL = False):
        #self.connParameters.ssl = isSSL
        self.conn = pika.BlockingConnection(self.connParameters)
        logging.info("new mq connection initiated")
        return self.conn

    def closeConn(self):
        self.conn.close()

    def clear(self):
        if self.channel is not None and (not self.channel.is_closed):
            self.channel.close()
        if self.conn is not None and (not self.conn.is_closed):
            self.conn.close()

    def initNewChannel(self, prefetchCount = 50):
        if self.conn is None:
            return False
        self.channel = self.conn.channel()
        self.channel.basic_qos(prefetch_count=50)
        logging.info("new mq channel initiated")
        return self.channel

    def bindQueue(self, queueName, exchangeName):
        self.channel.queue_declare(durable = True, queue = queueName)
        self.channel.queue_bind(None, queue = queueName, exchange = exchangeName, nowait = True)

    def initExchangeAndQueue(self, queueList, exchange = "", exchangeType = "direct"):
        if exchange != "":
            self.channel.exchange_declare(exchange = exchange, exchange_type = exchangeType)
        for queueName in queueList:
            self.channel.queue_declare(durable = True, queue = queueName)
            if exchange != "":
                self.channel.queue_bind( queue = queueName, exchange = exchange)

    def publishMsg(self, msg, routingKey, exchange = "", exchangeType = "direct"):
        self.channel.basic_publish(exchange = exchange,
                              routing_key = routingKey,
                              body = msg,
                              properties=pika.BasicProperties(
                                 delivery_mode = 2, # make message persistent
                              ))

    def callback(self, ch, method, properties, body):
        self.receiveCount += 1
        print("receive the {} message {}".format(self.receiveCount, unicode(body, "utf-8")))
        ch.basic_ack(delivery_tag = method.delivery_tag)
        if self.receiveCount >= 100:
            ch.close()
            self.closeConn()

    def consumeMsg(self, queueName, prefetchCount = 50, consumeCallback = None, no_ack = False):
        if consumeCallback is None:
            consumeCallback = self.callback
        self.channel.queue_declare(durable = True, queue = queueName)
        self.channel.basic_qos(prefetch_count=prefetchCount)
        self.consumeTag = self.channel.basic_consume(
            queue=queueName,
            on_message_callback=consumeCallback,
            auto_ack=no_ack,
        )
        self.channel.start_consuming()


if __name__ == "__main__":
    host = "47.94.3.136"
    #host = "127.0.0.1"
    port = 5672
    user = "C7knaNu5Z9O"
    passwd = "nGVgnlq1448"
