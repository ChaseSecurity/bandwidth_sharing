# Shining Light into the Tunnel: Understanding and Classifying Network Traffic of Residential Proxies

## Code Details

`domain_len.py`: Used to analyze the domain name of the specified pcap file and return the traffic size corresponding to each domain name.
   + You can use `python3 domain_len.py /path/to/pcap/file/` for test. It will generate a json file to store the results.


## Usage

```bash
python3 domain_len.py /path/to/pcap/file/
```


<!-- **Notes**:
+ You can get help by using `-h` option, e.g., `python3 time_machine.py -h`.
+ `config_template.yaml` should be updated, especially `provider` field.
+ `--alive_seed_file` should be provided by a file with domains you want to snapshot.
+ Option `--data_dir` is prioritized over the `data_dir` field in `config_template.yaml`.
+ You can select the step(s) you want `time_machine_pipeline.py` to do by option `--steps`. -->