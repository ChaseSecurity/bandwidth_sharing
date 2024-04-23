#!/bin/bash
sudo chown -R $USER:$USER /home/$USER/webspace
sudo sed "s/<USER>/$USER/g" ./ssl.conf.template > ./ssl.conf
sudo cp ./ssl.conf /etc/apache2/sites-available/
sudo ln -sf  /etc/apache2/sites-available/ssl.conf /etc/apache2/sites-enabled/ssl.conf 
sudo ln -sf  /etc/apache2/mods-available/ssl.conf /etc/apache2/mods-enabled/ssl.conf 
sudo ln -sf  /etc/apache2/mods-available/ssl.load /etc/apache2/mods-enabled/ssl.load
sudo ln -sf /etc/apache2/mods-available/socache_shmcb.load /etc/apache2/mods-enabled/socache_shmcb.load
cp -r ./certificates /home/$USER/webspace/
sudo chown -R www-data:www-data /home/$USER/webspace
sudo service apache2 restart
sudo service apache2 status
