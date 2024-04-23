This directory includes all the client-side programs for infiltration and device fingerprinting.
* The client to send infiltration traffic and grab response
* The client to send out device fingerprinting traffic
* The client to grab infiltration results and save to db and local file sytem

## Prior Requirements
You need to get the server-side programs running, including the web server, the dns server, and the message queue (rabbitMQ). Please follow the instructions in 
[the web_server directory](https://github.com/mixianghang/RPaaS/tree/master/infiltration_servers/web_server).
## Initialization
```
./clientInit.sh
source ./env/bins/activate
pip install -r ./requirements.txt
```

## Client to send out infiltration traffic
The following script is used to send infiltration probes. As denoted in the CLI help. You need to set up the infiltration config for each proxy provider, following the template in [proxy_providers](https://github.com/mixianghang/RPaaS/tree/master/infiltration_clients/proxy_providers).
```
python3 ./collectProxyNodes.py -h

positional arguments:
  config_file

optional arguments:
  -h, --help            show this help message and exit
  -to TIMEOUT, --timeout TIMEOUT
  -nt NUM_THREADS, --num_threads NUM_THREADS
  -rd RESULT_DIR, --result_dir RESULT_DIR
```

## Client for device fingerprinting
infiltration_ofp.py will grab fingerprinting tasks from the message queue, send out probings and save responses to local file system for offline device inferrence.
Still, you need an fingerprinting config file, as templated in *infiltration_ofp.cfg*, to provide addresseses and credentials for accessing the message queue.
```
python3 ./infiltration_ofp.py  -h
usage: infiltration_ofp.py [-h] [-ntmc NUM_THREADS_MC] [-ntfp NUM_THREADS_FP]
                           [-to TIMEOUT]
                           mqConfig resultDir

positional arguments:
  mqConfig
  resultDir

optional arguments:
  -h, --help            show this help message and exit
  -ntmc NUM_THREADS_MC, --num_threads_mc NUM_THREADS_MC
  -ntfp NUM_THREADS_FP, --num_threads_fp NUM_THREADS_FP
  -to TIMEOUT, --timeout TIMEOUT
```

## Client to log infiltration results
infiltration clients can be deployed across machines, and their results will be sent to message queue for further aggregation. We have another client to collect infiltration results 
into a physical server with enough storage space. 
```
python3 ./infiltration_logger.py  ./infiltration_logger.cfg -h
usage: infiltration_logger.py [-h] [-nt NUM_THREADS] [-to TIMEOUT]
                              mqConfig resultDir

positional arguments:
  mqConfig
  resultDir

optional arguments:
  -h, --help            show this help message and exit
  -nt NUM_THREADS, --num_threads NUM_THREADS
  -to TIMEOUT, --timeout TIMEOUT
```

## Backup the Webservers
We have another script to backup the web servers in terms tcpdumps and server-side web logs. It requires no-password ssh access to the web server
```
./backup_webserver.sh
server result_dir [curr_start_date (2019-04-15)] [curr_end_date (2019-05-01)]
```
