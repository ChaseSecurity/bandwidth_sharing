docker stop hgclient1; docker rm hgclient1; # docker rmi honeygain/honeygain;

selfDefinedNetwork=my_network
subnetwork=172.19.0.0/16
gateway=172.19.0.1
provider=honeygain
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

mkdir traffic
chmod 777 ./traffic

# nohup sudo tcpdump -i ${my_interface} -w ./traffic/${provider}_aspServer_%Y-%m-%d_%H-%M-%S.pcap "host 172.19.0.3" -W 90 -G 86400 &

sudo tcpdump -i ${my_interface} -w ./traffic/${provider}_$4_%Y-%m-%d_%H-%M-%S.pcap "host $1" -W $2 -G $3

docker stop hgclient1; docker rm hgclient1;
