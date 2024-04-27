# Code Details

`get_mail.py`: This Python script is designed to parse the smtp protocol in the pcap file and extract the email content and other information (server name, server ip, sender's email, receiver's email, etc.).
   + You can use `python3 get_mail.py /path/to/pcap/file/` for test. It will generate a json file to store the results.

`find_template_packetstream.py`: This Python script is designed to count the number of emails for each template in packetstream emails, and be able to calculate the number of successfully sent.
   + You can use `python3 find_template_packetstream.py` for test.It will output the result to the console.

`get_scale_of_email_delivery_traffic.py`: This Python script is designed to calculate the number and proportion of emails received by each different recipient's mailbox, and output the number of emails successfully sent and the number of errors at different stages.
   + You can use `python3 get_scale_of_email_delivery_traffic.py` for test. It will generate a json file to store the results.

`get_server_ip.py`: This Python script is designed to count all mail server IPs.
   + You can use `python3 get_server_ip.py` for test. It will generate a json file to store the results.

`get_suffix.py`: This Python script is designed to count the number of mailboxes corresponding to the domain names of the sender and recipient email service providers.
   + You can use `python3 get_suffix.py` for test. It will generate a json file to store the results.

`get_server_ip.py`: This Python script is designed to count all mail server IPs.
   + You can use `python3 get_server_ip.py` for test. It will generate a json file to store the results.
# Usage

```bash
python3 get_mail.py /path/to/pcap/file/
python3 find_template_packetstream.py
python3 get_scale_of_email_delivery_traffic.py
python3 get_server_ip.py
python3 get_suffix.py
python3 get_server_ip.py
```


<!-- **Notes**:
+ You can get help by using `-h` option, e.g., `python3 time_machine.py -h`.
+ `config_template.yaml` should be updated, especially `provider` field.
+ `--alive_seed_file` should be provided by a file with domains you want to snapshot.
+ Option `--data_dir` is prioritized over the `data_dir` field in `config_template.yaml`.
+ You can select the step(s) you want `time_machine_pipeline.py` to do by option `--steps`. -->