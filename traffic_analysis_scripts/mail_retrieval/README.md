# Code Details

`mail_retrieval.py`: This Python script is designed to save all IMAP and POP3 mail contents and other information.
   + You can use `python3 mail_retrieval.py /path/to/pcap/file/` for test. It will generate a json file to store the results.


# Usage

```bash
python3 mail_retrieval.py /path/to/pcap/file/
```


<!-- **Notes**:
+ You can get help by using `-h` option, e.g., `python3 time_machine.py -h`.
+ `config_template.yaml` should be updated, especially `provider` field.
+ `--alive_seed_file` should be provided by a file with domains you want to snapshot.
+ Option `--data_dir` is prioritized over the `data_dir` field in `config_template.yaml`.
+ You can select the step(s) you want `time_machine_pipeline.py` to do by option `--steps`. -->