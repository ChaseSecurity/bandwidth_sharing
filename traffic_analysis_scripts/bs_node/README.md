# Code Details

`gen_ip_stat.py`: This Python script is designed to analyze the json file generated by infiltration_scripts and return the total number of ips for packetstream and Iproyal, as well as statistics for the 16-bit prefix and 24-bit prefix of the ip address.
   + You can use `python3 gen_ip_stat.py` for test. It will generate three json file to store the results.(`stat.json`,`packetstream.json`,`iproyal.json`)

`get_dataset_ip.py`: This Python script is designed to analyze three data sets from the previous resip proxy data set: IP_Groups_Providers.json, proxy_IPs.tsv, ip_captured_as_web_proxy.tsv, and return the number of each ip address.
   + You can use `python3 get_dataset_ip.py` for test. It will generate a json file to store the results.(`dataset_ip.json`)

`read.py`: This Python script is designed to analyze the data generated by the previous two py files and get the number of penetration probes we captured that we sent. In addition, the number of IP addresses that overlap with the previously studied resip proxy data set will also be output.
   + You can use `python3 read.py` for test. It will output the results to the console.


# Usage

```bash
python3 gen_ip_stat.py
python3 get_dataset_ip.py
python3 read.py
```


<!-- **Notes**:
+ You can get help by using `-h` option, e.g., `python3 time_machine.py -h`.
+ `config_template.yaml` should be updated, especially `provider` field.
+ `--alive_seed_file` should be provided by a file with domains you want to snapshot.
+ Option `--data_dir` is prioritized over the `data_dir` field in `config_template.yaml`.
+ You can select the step(s) you want `time_machine_pipeline.py` to do by option `--steps`. -->