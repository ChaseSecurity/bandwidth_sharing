#! /usr/bin/env bash
for d in "$@";do
	file_dir=$d
        for file in $file_dir/*
        do
                if [ -s $file ] && [ "${file##*_v2.}"x = "json"x ];
                then
                        echo $file >> src_all.txt
			python3 no_find_port.py $file 25 993 30944 5222 5223 6666 6667

                else
                        echo "$file is empty or not _.json file"
                fi
                        
        done
done
