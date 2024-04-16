#! /usr/bin/env bash
for d in "$@";do
	file_dir=$d
        for file in $file_dir/*
        do
                if [ -s $file ] && [ "${file##*_v2.}"x = "json"x ];
                then
			python3 get_sensitive_domain.py $file
                else
                        echo "$file is empty or not v2 json file"
                fi
                        
        done
done
