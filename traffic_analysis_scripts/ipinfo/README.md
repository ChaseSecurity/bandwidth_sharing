# Code Details

`ipinfo_api.py`: This Python script is designed to use the ip set, domain set, and url set obtained by (../ip_domain_url/) to make requests using the Ipinfo api.
   + You can use `python ipinfo_api.py /path/to/new/domains.txt /path/to/passive/domains.txt /path/to/output/results.txt` for test. It will generate a json file to store the results.

`read.py`: This Python script is designed to read the output of ipinfo_api.py and then print out the number of IPs in each country and the proportion.
   + You can use `python read.py` for test. 

# Usage

```bash
python3 ipinfo_api.py /path/to/new/domains.txt /path/to/passive/domains.txt /path/to/output/results.json
python3 read.py 
```


<!-- **Notes**:
+ You can get help by using `-h` option, e.g., `python3 time_machine.py -h`.
+ `config_template.yaml` should be updated, especially `provider` field.
+ `--alive_seed_file` should be provided by a file with domains you want to snapshot.
+ Option `--data_dir` is prioritized over the `data_dir` field in `config_template.yaml`.
+ You can select the step(s) you want `time_machine_pipeline.py` to do by option `--steps`. -->