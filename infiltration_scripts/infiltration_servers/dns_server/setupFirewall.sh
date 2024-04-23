sudo iptables -A INPUT -p udp --dport 53 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 53 -j ACCEPT
sudo apt-get update
sudo apt-get install iptables-persistent
sudo netfilter-persistent save
