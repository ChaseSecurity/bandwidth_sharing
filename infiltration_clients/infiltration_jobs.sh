#!/bin/bash
INFI_NUM=50
SSL_NUM=20
if [ $# -lt 2 ];then
    echo 'Usage env_dir cfg_dir result_dir'
    exit 1
fi
client_dir=$(dirname $0)
client_dir=$(cd $client_dir && pwd)
env_dir=$1
cfg_dir=$2
result_base_dir=$3
# init python envrironment
source $env_dir/bin/activate
curr_ds=$(date +'%Y%m%d')
echo "client dir is $client_dir"
echo "env dir is $env_dir"
echo "cfg dir is $cfg_dir"
echo "result base dir is $result_base_dir"
echo "curr ds is $curr_ds"
result_dir=$result_base_dir/$curr_ds
if [ ! -e $result_dir ];then
    mkdir -p $result_dir
fi
# set up infiltration logger
python3 $client_dir/infiltration_logger.py $cfg_dir/infiltration_logger.cfg  $result_dir/logs -nt 10 -to 80000 1>$result_dir/logs_daily.log 2>&1 &
if [ $? -eq 0 ];then
    echo "set up logger"
else
    echo "failed to set up logger"
    exit 1
fi

# set up infiltration ofp
python3 $client_dir/infiltration_ofp.py $cfg_dir/infiltration_ofp.cfg  $result_dir/ofp -ntmc 10 -ntfp 50 -to 80000 1>$result_dir/ofp_daily.log 2>&1 &
if [ $? -eq 0 ];then
    echo "set up ofp"
else
    echo "failed to set up ofp"
    exit 1
fi

# set up infiltration node
python3 $client_dir/collectProxyNodes.py $cfg_dir/infiltration.cfg -rd $result_dir/collectProxyNodes -to 75000 -nt $INFI_NUM 1>$result_dir/collectProxyNodes_daily.log 2>&1 &
if [ $? -eq 0 ];then
    echo "set up node collector"
else
    echo "failed to set up node collector"
    exit 1
fi
