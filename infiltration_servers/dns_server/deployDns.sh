#!/bin/bash
sudo ./setupFirewall.sh
sudo apt-get install -y bind9
sudo cp -r ./bind/* /etc/bind/
sudo service bind9 restart
sudo service bind9 status
echo 'deployment is done'
