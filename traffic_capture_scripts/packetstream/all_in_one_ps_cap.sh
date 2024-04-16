# USAGE: ./ps_cap.sh [assigned_ip] 
# E.g. ./ps_cap.sh 172.19.0.2 or 172.8.0.2 (ip should be aligned with line 8)
# echo "the file name(including execution path) is $0" 
# echo "the assigned ip is $1"
# create a user-defined bridge network my_network
# by default, it is a bridge network(--driver bridge) with default subnet(--subnet 172.8.0.0/16, or other subnet if 172.8.xx is occupied, check it with 'docker network inspect my_network') and default gateway(--gateway 172.8.0.1)
# you can inspect this network with `docker network inspect my_network`


selfDefinedNetwork=my_network
subnetwork=172.19.0.0/16
gateway=172.19.0.1
if docker network ls | grep -q ${selfDefinedNetwork};
then
	networkHash=$(docker network ls | grep ${selfDefinedNetwork})
	networkShortID=${networkHash:0:12}
	echo ${selfDefinedNetwork}" exists."
else
	echo ${selfDefinedNetwork}" not exist. Create it."
	networkShortID=$(docker network create --driver bridge --subnet ${subnetwork} --gateway ${gateway} my_network)
fi
# get bridge interface name
my_interface="br-"${networkShortID:0:12}
echo $my_interface
echo "subnetwork:"${subnetwork}
echo "gateway:"${gateway}

# capture traffic on assigned_ip which will later be assigned to the docker container
# rotation saving pcap file with duration 1d and file limit 30.
# ERROR: no permission as root.
sudo nohup tcpdump -i ${my_interface} -w packetstream_iuserver_$(date +%H%M%S_%m_%d).pcap "host $1" -W 30 -G 86400 &
#sudo tcpdump -i ${my_interface} -w packetstream_iuserver_$(date +%H%M%S_%m_%d).pcap "host $1"
# run a container named "psclient1" with assigned ip
# you should use your own [CID]
docker stop psclient1; docker rm psclient1; docker rmi packetstream/psclient; docker run -d --restart=always -e CID=2jWq --name psclient1 --net my_network --ip ${1} --dns 8.8.8.8 packetstream/psclient:latest
