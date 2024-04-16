This directory includes all the server-side programs and helper scripts for infiltration.
* The web server to serve infiltration traffic
* The authoritative DNS server to serve DNS queries
* The message queue to serve as the task dispatcher

## Prior Requirements
Apparently, you need to get a server set up, which can be either a physical server or a virtual machine.
Those programs eat very small amount of CPUs and memory, and even an AWS EC2 free tier virtual machine is enough.

## Initializationy
* Purchase a domain
* Get SSL certificates if you want to send out HTTPS infiltration traffic, put the certificates in web_server/certificates/
* If with ssl certificate, modify ssl.conf.template which will be used by the web server to serve HTTPS traffic

## Web server
Given a server *$server* and you have set up no-password ssh access, run the following command to deploy the web application.
This script will upload the whole sub directory to the server, and install necessary components such as Apache.
```
cd web_server
./runRemote.sh $server
```

## Authoriotative DNS server
Similar to the web server
```
cd dns_server
./runRemote.sh $server
```

## RabbitMQ
Change deployRabbitMq.sh to set up the user and password. The user and password along with the server addresses will be used by clients to retrieve results from the message queue.
On the given server, run the following command to set up a working message queue.
```
./deployRabbitMq.sh
```
