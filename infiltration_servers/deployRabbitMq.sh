#!/bin/bash
user="C7knaNu5Z9O"
passwd="nGVgnlq1448"
sudo apt install -y rabbitmq-server
sudo rabbitmqctl add_user $user $passwd
sudo rabbitmqctl set_user_tags $user administrator
sudo rabbitmqctl set_permissions -p / $user ".*" ".*" ".*"
sudo rabbitmqctl delete_user guest
sudo rabbitmq-plugins enable rabbitmq_management
