#!/bin/bash
sudo apt-get install -y apache2 apache2-utils
user=$USER
mkdir -p /home/$user/webspace
mkdir -p /home/$user/logs/webproxy
mkdir -p /home/$user/logs/tcpdump
# start tcpdump, seems not work after the bash is done
nohup sudo tcpdump -i any -K -n -w /home/$user/logs/tcpdump/%Y-%m-%d-%H_tcpdump.pcap -G 3600  port not 22 &
sudo chown -R $user:$user /home/$user/webspace/
cp -r webproxy /home/$user/webspace
sudo chown -R www-data:www-data /home/$user/webspace/
sudo sed "s/<USER>/$USER/g" ./000-default.conf.template > ./000-default.conf
sudo cp ./000-default.conf /etc/apache2/sites-available/
sudo ln -s /etc/apache2/mods-available/rewrite.load /etc/apache2/mods-enabled/rewrite.load
sudo apt-get install -y php libapache2-mod-php php-mcrypt php-mysqlsudo apt-get install -y php libapache2-mod-php php-mysql
# Install prerequisites
# sudo apt-get install -y php-dev libmcrypt-dev gcc make autoconf libc-dev pkg-config

# Compile mcrypt extension
# sudo pecl install mcrypt-1.0.1
# Just press enter when it asks about libmcrypt prefix

# Enable extension for apache for new php versions
echo "extension=mcrypt.so" | sudo tee -a /etc/php/7.2/apache2/conf.d/mcrypt.ini
sudo service apache2 restart
./configureSSL.sh
