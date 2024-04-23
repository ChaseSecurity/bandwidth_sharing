# Code Details

`urlhaus_api.py`: This Python script is designed to use the ip set, domain set, and url set obtained by (../ip_domain_url/) to make requests using the urlhaus api.
   + You can use `python urlhaus_api.py /path/to/new/domains.txt /path/to/passive/domains.txt /path/to/output/results.txt` for test. It will generate a json file to store the results.


# Usage

```bash
python urlhaus_api.py /path/to/new/domains.txt /path/to/passive/domains.txt /path/to/output/results.json

```


<!-- **Notes**:
+ You can get help by using `-h` option, e.g., `python3 time_machine.py -h`.
+ `config_template.yaml` should be updated, especially `provider` field.
+ `--alive_seed_file` should be provided by a file with domains you want to snapshot.
+ Option `--data_dir` is prioritized over the `data_dir` field in `config_template.yaml`.
+ You can select the step(s) you want `time_machine_pipeline.py` to do by option `--steps`. -->