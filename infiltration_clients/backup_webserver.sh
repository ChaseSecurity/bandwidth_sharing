#!/bin/bash
if [ $# -lt 2 ];then
    echo "server result_dir [curr_start_date (2019-04-15)] [curr_end_date (2019-05-01)]"
    exit 1
fi
server=$1
result_dir=$2
if [ $# -ge 4 ];then
    start_date=$(date -d $3 +"%Y-%m-%d")
    end_date=$(date -d $4 +"%Y-%m-%d")
else
    start_date=$(date +"%Y-%m-%d")
    end_date=$curr_start_date
fi
echo "backup periods $start_date and $end_date"
curr_date=$start_date
while [[ $curr_date < $end_date || $curr_date == $end_date ]] ;
do
    echo $curr_date
    #backup tcpdump
    tcpdump_dir=$result_dir/tcpdumps/$server
    if [ ! -e $tcpdump_dir ];then
        mkdir -p $tcpdump_dir
    fi
    scp $server:/rpaas_logs/tcpdump/${curr_date}* $tcpdump_dir/
    if [ $? -ne 0 ];then
        echo "Error when backuping tcpdump for date ${curr_date}"
    fi

    # rm server-side data
    ssh -t $server "rm -f /rpaas_logs/tcpdump/${curr_date}*"

    # backup web server log
    curr_date_1=$(date -d "$curr_date" +"%Y_%m_%d")
    weblog_dir=$result_dir/weblogs/$server
    if [ ! -e $weblog_dir ];then
        mkdir -p $weblog_dir
    fi
    scp $server:/rpaas_logs/webproxy/${curr_date_1}* $weblog_dir/
    if [ $? -ne 0 ];then
        echo "Error when backuping webproxy logs for date ${curr_date}"
    fi
    # rm server-side data
    ssh -t $server "rm -f /rpaas_logs/webproxy/${curr_date_1}*"
    curr_date=$(date -d "$curr_date +1day" +"%Y-%m-%d")
done
