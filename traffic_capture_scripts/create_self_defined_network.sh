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
#echo ${networkShortID}
my_interface="br-"${networkShortID:0:12}
echo $my_interface
echo "subnetwork:"${subnetwork}
echo "gateway:"${gateway}
