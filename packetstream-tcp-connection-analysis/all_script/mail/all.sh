#! /usr/bin/env bash
for d in "$@";do
	file_dir=$d
        for file in $file_dir/*
        do
                if [ -s $file ] && [ "${file##*_v3.}"x = "json"x ];
                then
                        echo $file >> src_all.txt
			python3 get_mail.py $file

                else
                        echo "$file is empty or not _v3.json file"
                fi
                        
        done
done
