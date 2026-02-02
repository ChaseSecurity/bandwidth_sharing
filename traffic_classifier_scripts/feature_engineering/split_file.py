import argparse
import json
import os
import shutil
import sys

source_pcap_dir=''
output_split_dir=''
# label 0,1

def split_pcap(filename, files_path_set, files_path_list, include_udp=False):

    if os.path.basename(filename) in files_path_set:
        return False, True

    # Fast skip: if not including UDP, and this file is UDP-only, skip without logging.
    if not include_udp:
        try:
            with open(filename, 'r') as probe_file:
                for probe_line in probe_file:
                    probe_line = probe_line.strip()
                    if not probe_line:
                        continue
                    probe_stat = json.loads(probe_line)
                    if probe_stat[6] != 'tcp':
                        return False, True
                    break
        except Exception:
            return False, True

    in_file=open(filename,'r')
    processed = False
    for line in in_file:
        line = line.strip()
        if not line:
            continue
        stat=json.loads(line)
        if stat[6]=='tcp' or (include_udp and stat[6]=='udp'):
            base_name = stat[8]
            src_ip = stat[1].replace('.','-')
            dst_ip = stat[3].replace('.','-')
            src_port = str(stat[2])
            dst_port = str(stat[4])

            if ".pcap.TCP_" in base_name and base_name.endswith(".pcap"):
                pcap_folder = base_name.split(".pcap.TCP_")[0] + ".pcap"
                candidates = [base_name]
                candidates.append(f"{pcap_folder}.TCP_{src_ip}_{src_port}_{dst_ip}_{dst_port}.pcap")
                candidates.append(f"{pcap_folder}.TCP_{dst_ip}_{dst_port}_{src_ip}_{src_port}.pcap")
            else:
                pcap_folder = base_name
                candidates = [
                    f"{base_name}.TCP_{src_ip}_{src_port}_{dst_ip}_{dst_port}.pcap",
                    f"{base_name}.TCP_{dst_ip}_{dst_port}_{src_ip}_{src_port}.pcap",
                ]

            copied = False
            for copy_filename in candidates:
                copy_from = os.path.join(source_pcap_dir, pcap_folder, copy_filename)
                if stat[0]==1:
                    copy_to = os.path.join(output_split_dir, '1', copy_filename)
                elif stat[0]==0:
                    copy_to = os.path.join(output_split_dir, '0', copy_filename)
                else:
                    continue
                if os.path.exists(copy_from):
                    shutil.copy(copy_from, copy_to)
                    copied = True
                    break
            if not copied:
                print('Neither file exists?!')
            else:
                processed = True

    if processed:
        base = os.path.basename(filename)
        files_path_set.add(base)
        files_path_list.append(base)
        return True, False
    return False, False


def load_stat_files():
    try:
        with open('stat.json', 'r') as input_json:
            input_stat = json.load(input_json)
        files_path_list = input_stat.get('files_path', [])
        return set(files_path_list), files_path_list
    except Exception:
        return set(), []


def write_stat_files(files_path_list):
    output_stat = {}
    # output_stat['all_len']=all_len
    # output_stat['all_base_tcp_len']=all_base_tcp_len
    output_stat['files_path'] = files_path_list
    with open('stat.json', 'w') as output_json:
        json.dump(output_stat, output_json)



def main():
    parser = argparse.ArgumentParser(description="Split labeled flow JSON into class folders.")
    parser.add_argument("input_json", help="Path to a flow JSON file or a directory of JSON files.")
    parser.add_argument("--source_pcap_dir", required=True,
                        help="Directory containing per-pcap folders to copy from.")
    parser.add_argument("--output_split_dir", required=True,
                        help="Output directory where class subfolders (0/1) will be created.")
    parser.add_argument("--include_udp", action="store_true",
                        help="Also copy UDP flows (default: TCP only).")
    parser.add_argument("--progress_every", type=int, default=1000,
                        help="Print progress every N files (default: 1000).")
    args = parser.parse_args()

    global source_pcap_dir, output_split_dir
    source_pcap_dir = os.path.expanduser(args.source_pcap_dir)
    output_split_dir = os.path.expanduser(args.output_split_dir)

    if not os.path.isdir(source_pcap_dir):
        raise FileNotFoundError(f"source_pcap_dir not found: {source_pcap_dir}")
    os.makedirs(os.path.join(output_split_dir, '0'), exist_ok=True)
    os.makedirs(os.path.join(output_split_dir, '1'), exist_ok=True)

    files_path_set, files_path_list = load_stat_files()

    if os.path.isdir(args.input_json):
        print('Processing directory:', args.input_json)
        processed_count = 0
        skipped_count = 0
        total_count = 0
        for name in sorted(os.listdir(args.input_json)):
            if not name.endswith('.json'):
                continue
            file_path = os.path.join(args.input_json, name)
            processed, skipped = split_pcap(
                file_path,
                files_path_set,
                files_path_list,
                include_udp=args.include_udp,
            )
            if processed:
                processed_count += 1
            if skipped:
                skipped_count += 1
            total_count += 1
            if args.progress_every > 0 and total_count % args.progress_every == 0:
                write_stat_files(files_path_list)
                print(f"Progress: processed={processed_count}, skipped={skipped_count}, total={total_count}")
        write_stat_files(files_path_list)
    else:
        print('Processing file:', args.input_json)
        processed, skipped = split_pcap(
            args.input_json,
            files_path_set,
            files_path_list,
            include_udp=args.include_udp,
        )
        print('Finished file:', args.input_json)
        if args.progress_every > 0:
            print(f"Progress: processed={int(processed)}, skipped={int(skipped)}, total={int(processed) + int(skipped)}")
        if processed:
            write_stat_files(files_path_list)

if __name__ == "__main__":
    main()
