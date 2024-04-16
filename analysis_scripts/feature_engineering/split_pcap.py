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
    # 确保输出目录存在
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    # 遍历输入目录中的所有文件
    for filename in os.listdir(input_directory):
        if filename.endswith(".pcap") and (filter_string is None or filter_string in filename):
            input_file_path = os.path.join(input_directory, filename)
            # 为每个pcap文件创建一个单独的输出目录
            file_output_directory = os.path.join(output_directory, filename)
            if not os.path.exists(file_output_directory):
                os.makedirs(file_output_directory)
            # 构建SplitCap命令
            command = [enable, splitcap_path, "-r", input_file_path, "-o", file_output_directory, "-p", str(parallel_sessions)]
            # 执行命令
            subprocess.run(command)


if __name__ == "__main__":
    output_dir = "/path/to/output/dir/"
    input_dir = "/path/to/input/dir/"
    filter_str = "iproyal"
    split_pcap_files(input_dir, output_dir, filter_string=filter_str)


