# run a container named "psclient1"
# you should use your own [CID]
docker stop psclient1; docker rm psclient1; docker rmi packetstream/psclient; docker run -d --restart=always -e CID=2jWq --name psclient1 packetstream/psclient:latest
# get the internel IP of running container named psclient1
IP1=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' psclient1)
# Capture the sent/received traffic through ${IP1}
# To rotate capture the traffic based on time. The following command is capturing traffic for 30 days. 
# Save a file every 86400s(24h). Up to 30 files.  
tcpdump -i docker0 -w packetstream_date+%s_%m_%d.pcap "host ${IP1}" -W 30 -G 86400
