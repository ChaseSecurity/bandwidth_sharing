import argparse
import os
import subprocess


def split_pcap_files(input_directory, output_directory, splitcap_path="SplitCap.exe", enable="mono",
                     parallel_sessions=1018, filter_string=None):
    """
    分解指定路径及其子目录中的所有pcap文件到指定的文件夹

    :param input_directory: 包含pcap文件的输入目录路径
    :param output_directory: 输出目录路径，分解后的文件将存储在这里
    :param splitcap_path: SplitCap可执行文件的路径
    :param enable: 可执行文件的环境
    :param parallel_sessions: 同时保持在内存中的并行会话数量
    :param filter_string: 用于过滤文件的字符串，只有文件名包含这个字符串的文件才会被分割
    """
    # Normalize paths and ensure output directory exists
    input_directory = os.path.expanduser(input_directory)
    output_directory = os.path.expanduser(output_directory)
    if not os.path.isdir(input_directory):
        raise FileNotFoundError(f"Input directory not found: {input_directory}")
    os.makedirs(output_directory, exist_ok=True)

    # 遍历输入目录中的所有文件
    for filename in os.listdir(input_directory):
        if filename.endswith(".pcap") and (filter_string is None or filter_string in filename):
            input_file_path = os.path.join(input_directory, filename)
            # 为每个pcap文件创建一个单独的输出目录
            file_output_directory = os.path.join(output_directory, filename)
            os.makedirs(file_output_directory, exist_ok=True)
            # 构建SplitCap命令
            command = [enable, splitcap_path, "-r", input_file_path, "-o", file_output_directory, "-p", str(parallel_sessions)]
            # 执行命令
            subprocess.run(command)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Split pcap files into per-flow sessions.")
    parser.add_argument("--input_dir", required=True, help="Directory containing .pcap files.")
    parser.add_argument("--output_dir", required=True, help="Directory to write split output.")
    parser.add_argument("--filter", dest="filter_str", default=None,
                        help="Only split files whose name contains this string.")
    parser.add_argument("--splitcap_path", default="SplitCap.exe", help="Path to SplitCap executable.")
    parser.add_argument("--enable", default="mono", help="Executable environment (e.g., mono).")
    parser.add_argument("--parallel_sessions", type=int, default=1018,
                        help="Number of parallel sessions to keep in memory.")
    args = parser.parse_args()

    split_pcap_files(
        args.input_dir,
        args.output_dir,
        splitcap_path=args.splitcap_path,
        enable=args.enable,
        parallel_sessions=args.parallel_sessions,
        filter_string=args.filter_str,
    )


