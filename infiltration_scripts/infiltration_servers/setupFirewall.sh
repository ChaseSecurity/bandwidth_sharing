sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 5672 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 15672 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 25672 -j ACCEPT
sudo iptables -A INPUT -p udp -m udp --dport 60000:61000 -j ACCEPT
sudo iptables -I INPUT 1 -i lo -j ACCEPT
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
sudo iptables -P INPUT DROP
sudo apt-get update
sudo apt-get install iptables-persistent
sudo netfilter-persistent save
