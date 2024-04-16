#!/usr/bin/bash
remote_server_file=${1:-remote_server_file}
ssh_key=${2:-"id_rsa"}
curr_date=${3:-$(date +"%Y-%m-%d")}
base_result_dir=${4:-/backup}
src_dir_to_sync=${5:-backup}   # backup的module名
date_to_cleanup=$(date +"%Y-%m-%d" -d "${curr_date}-3days")
real_path=${6:-"/root/hrh/bandwidth_sharing/traffic_capture_scripts"}
step_dir="traffic"
cat $remote_server_file | while read server || [ -n "$server" ];


do
    echo "$(date) Backup and cleanup server $server"
    # echo "$(date) rsync -azvv $server:$src_dir_to_sync $base_result_dir/${src_dir_to_sync}_${server}"
    # rsync -azvv $server:$src_dir_to_sync/ $base_result_dir/${src_dir_to_sync}_${server}/
    # echo "Cleanup data of ${date_to_cleanup} for server $server"
    for provider in "packetstream";
    do
      for server_dir in "pfs-beijing"  "vps1" "vps2" "vps3";
      do
        src_dir_to_remove=${src_dir_to_sync}/${provider}/${step_dir}/${server_dir} #/${date_to_cleanup}  #远程的文件夹
        backup_dir=$base_result_dir/${src_dir_to_sync}_${server}/${provider}/${step_dir}/${server_dir} #/${date_to_cleanup}

        if [[ ! -d $backup_dir ]];then
          echo "Backup dir $backup_dir doesn't exist, build it"
          mkdir -p $backup_dir
        fi

        rsync -azvv $server::$src_dir_to_remove/ $backup_dir --password-file=/etc/rsync.passwd

        if [[ $? -ne 0 ]]; then
          echo "$(date) the backup of ${src_dir_to_remove} failed with non-zero exit code, skip space free up"
          continue
        fi

        du -hs $backup_dir
        echo "ssh -i $ssh_key -n $server \"du -hs ${real_path}/$provider/$step_dir/$server_dir && rm ${real_path}/$provider/$step_dir/$server_dir/*${date_to_cleanup}*.pcap\""
        # # -n prevents ssh from reading the stdin
        ssh -i $ssh_key -n $server "du -hs ${real_path}/$provider/$step_dir/$server_dir && rm ${real_path}/$provider/$step_dir/$server_dir/*${date_to_cleanup}*.pcap"
      done
    done
done
