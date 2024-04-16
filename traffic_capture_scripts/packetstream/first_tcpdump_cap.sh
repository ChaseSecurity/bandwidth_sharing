# USAGE: ./first_tcpdump_cap.sh [assigned_ip] [limit of the number of files] [capture time for each file]
# Sample: ./first_tcpdump_cap.sh 172.19.0.2 3 2 thisserver
# capture 6 seconds, save the traffic to 3 files each of which has 2-second traffic.

# remove potential conflict container and image. 

docker stop psclient1; docker rm psclient1; docker rmi packetstream/psclient;

# create a user-defined bridge network my_network if not exists.

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

# the directory to save captured traffic must be world-writable.
mkdir traffic
chmod 777 ./traffic

# capture traffic on assigned_ip which will later be assigned to the docker container
# rotation saving pcap file with duration $3 and file limit $2.
# $1 refers to the first parameter e.g. 172.19.0.2 in the usage sample command.
# $2 refers to the second para e.g. 3 in the usage sample command.
#sudo tcpdump -i ${my_interface} -w packetstream_$4_$(date +%H%M%S_%m_%d).pcap "host $1" -W 30 -G 86400
#sudo tcpdump -i ${my_interface} -w ./traffic/packetstream_$4_$(date +%H%M%S_%m_%d).pcap "host $1" -W $2 -G $3
# nohup sudo tcpdump -i ${my_interface} -w ./traffic/packetstream_aspServer_%Y-%m-%d_%H-%M-%S.pcap "host 172.19.0.2" -W 90 -G 86400 &
sudo tcpdump -i ${my_interface} -w ./traffic/packetstream_$4_%Y-%m-%d_%H-%M-%S.pcap "host $1" -W $2 -G $3

# clean unused container and image to save system storage
docker stop psclient1; docker rm psclient1; docker rmi packetstream/psclient;
