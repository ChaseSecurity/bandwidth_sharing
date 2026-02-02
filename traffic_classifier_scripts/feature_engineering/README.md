# Code Details

`split_pcap.py`: This script is used to split a complete pcap file into multiple small pcap files in the form of flows. Please place SplitCap.exe([Download](https://www.netresec.com/?page=SplitCap)) in the folder in advance. 
   + You can use `python split_pcap.py --input_dir=./input_dir/ --output_dir=./output_dir/` for test after creating ./input_dir/ and ./output_dir/.
   + Assumes all raw pcap files are in ./input_dir/
   + Be sure to have mono installed (e.g., brew install mono)

`out_label_relay.py`: This script is used to classify packetstream, iproyal, honeygain relayed flows and other flows, and save the results to a json file.
   + You can use `python out_label_relay.py ./output_dir` for test.
   + Outputs flow labels to `./flows/relay/`.

`out_label_tunnel.py`: This script is used to classify packetstream, iproyal, honeygain tunnel flows and other flows, and save the results to a json file.
   + You can use `python out_label_tunnel.py ./output_dir` for test.
   + Outputs flow labels to `./flows/tunnel/`.

`split_file.py`: This script is used to copy the pcap file with label 0/1 to the corresponding folder, input the json generated for out_label, and specify the folder where the pcap file is divided.
   + You can use `python split_file.py ./flows --source_pcap_dir ./output_dir --output_split_dir ./split_output --flow_type relay --progress_every 500` for test.
   + Use `--flow_type tunnel` with `./flows` for tunnel labels.

`train_and_test.py`: This script is used to train and test the model. After specifying the label folder, the model will be generated and the results will be output.
   + You can use `python3 train_and_test.py ./split_output/{relay | tunnel} --flow_type relay` for test.
   + Use `--flow_type tunnel` for tunnel labels.

# Usage

```bash
python split_pcap.py --input_dir=./input_dir/ --output_dir=./output_dir/
python out_label_relay.py ./output_dir
python out_label_tunnel.py ./output_dir
python split_file.py ./flows --source_pcap_dir ./output_dir --output_split_dir ./split_output --flow_type relay --progress_every 500
python split_file.py ./flows --source_pcap_dir ./output_dir --output_split_dir ./split_output --flow_type tunnel --progress_every 500
python train_and_test.py ./split_output/relay --dataset_dir ./dataset --model_dir ./model --flow_type relay
python train_and_test.py ./split_output/tunnel --dataset_dir ./dataset --model_dir ./model --flow_type tunnel
```


<!-- **Notes**:
+ You can get help by using `-h` option, e.g., `python3 time_machine.py -h`.
+ `config_template.yaml` should be updated, especially `provider` field.
+ `--alive_seed_file` should be provided by a file with domains you want to snapshot.
+ Option `--data_dir` is prioritized over the `data_dir` field in `config_template.yaml`.
+ You can select the step(s) you want `time_machine_pipeline.py` to do by option `--steps`. -->