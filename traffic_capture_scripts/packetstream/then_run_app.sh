# USAGE: ./then_run_app.sh [IP]
# run a container named "psclient1" with assigned ip
# you should use your own [CID]
docker stop psclient1; docker rm psclient1; docker rmi packetstream/psclient; docker run -d --restart=always -e CID=3lPo --name psclient1 --net my_network --ip ${1} --dns 8.8.8.8 packetstream/psclient:latest
