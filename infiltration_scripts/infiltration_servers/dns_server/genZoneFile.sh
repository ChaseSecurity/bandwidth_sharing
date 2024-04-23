#!/bin/bash
ip_list=$(/sbin/ip -o addr show scope global | grep eth0 | awk '{gsub(/\/.*/,"",$4); print $4}')
