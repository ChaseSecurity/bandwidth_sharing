#! /usr/bin/env bash
for d in "$@";do
	file_dir=$d
        for file in $file_dir/*
        do
                if [ -s $file ] && [ "${file##*_v3.}"x = "json"x ];
                then
                        echo $file >> src_all.txt
			python3 get_one_hour.py $file

                else
                        echo "$file is empty or not _.json file"
                fi
                        
        done
done
