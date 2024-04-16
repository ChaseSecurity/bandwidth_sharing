#! /usr/bin/env bash
for d in "$@";do
	file_dir=$d
        for file in $file_dir/*
        do
                if [ -s $file ] && [ "${file##*.}"x = "pcap"x ];
                then
                        echo $file >> src_all.txt
			python3 out_json.py $file
                else
                        echo "$file is empty or not pcap file"
                fi
                        
        done
done
