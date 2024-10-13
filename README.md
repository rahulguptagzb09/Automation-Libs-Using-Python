# Python Functions/Libraries for Automation

These libraries/functions are related to dictionaries (HashMaps), YAMLs, Files, Git, Linux Ubuntu, Docker, Kubernetes, Pcap Wireshark

PYTHON 3.10 INSTALLATION

To download python software from the below link and follow the standard application installation procedure.

    https://www.python.org/downloads/release/python-3103/

Environment variables to be configured for python.
    
    Open Start -> Settings -> Control Panel -> System -> Advanced -> Environment Variables
        C:\Python_3.10.3\
        C:\Python_3.10.3\Scripts\

To validate python is installed using below commands

    python --version

Package names and version are available in requirements.txt file.

    pip install -r requirements.txt

WIRESHARK 3.6.14 Windows INSTALLATION

Download “wireshark”  from below link and follow the standard application installation procedure.

	https://www.wireshark.org/download.html

WIRESHARK 3.6.14 Linux INSTALLATION - 

    wget https://1.eu.dl.wireshark.org/src/wireshark-3.6.14.tar.xz
    
    tar -xf wireshark-3.6.14.tar.xz
    
    sudo apt-get install cmake -y
    
    sudo apt-get install -y libglib2.0-dev libglib2.0-dev libc-ares-dev libgcrypt20-dev
    
    sudo apt-get install -y libglib2.0-dev flex bison libpcre2-dev libpcap-dev libnghttp2-dev
    
    sudo apt-get install -y qttools5-dev qttools5-dev-tools libqt5svg5-dev qtmultimedia5-dev
    
    sudo apt-get install -y build-essential
    
    cd wireshark-3.6.14/cmake
    
    sudo cmake ..
    
    sudo make
    
    sudo make install
    
    sudo ldconfig
    
    wireshark --version
	
WIRESHARK 3.6.14 Linux UNINSTALLATION - 

	The method is shown here: https://www.youtube.com/watch?v=WOJWbAyjflk

	sudo apt-get remove --autoremove wireshark wireshark-*

	sudo rm -rf /etc/wireshark

	check if everything is removed with whereis wireshark

# Documentation - 

Dictionary Utils - 
    
    def validate_dict_schema(input_dict: dict, schema_dict: dict = None, schema_json: str = None) -> dict:
    def lowercase_keys_dict(data: dict, ignore_keys: tuple = ()) -> dict:
    def uppercase_keys_dict(data: dict, ignore_keys: tuple = ()) -> dict:
    def get_keys_list_from_dict(data: dict, key_path_list: list) -> list:
    def get_value_from_key_path_dict(data: dict, key_path_list: list):
    def load_json(json_file: str) -> dict:
    def validate_data(data: dict, schema: dict = None) -> dict:

YAML Utils - 
    
    def validate_yaml_schema(yaml_file: str, schema_dict: dict = None, schema_json: str = None) -> dict:
    def lowercase_keys_yaml(input_file: str, output_file: str, ignore_keys: tuple = (), mapping: int = 2, sequence: int = 4, offset: int = 2) -> None:
    def uppercase_keys_yaml(input_file: str, output_file: str, ignore_keys: tuple = (), mapping: int = 2, sequence: int = 4, offset: int = 2) -> None:
    def get_keys_list_from_yaml(input_file: str, key_path_list: list) -> list:
    def load_yaml(yaml_file: str) -> dict:

File Utils - 
    
    def delete_files(path: str, days: int = 1, file_extension: str = "", file_name_starting: str = "") -> list:
    def split_file_by_lines(input_dir: str, output_dir: str, number_of_lines: int = 1) -> None:
    def find_lines_in_file_without_words(file_name: str, words: list) -> list:
    def create_html(path: str, fields: list, data: dict) -> None:
    def unzip_file(directory: str, zip_file_name: str) -> None:
    def get_latest_file(find_file_str: str, directory: str) -> str:
    def get_tag_value_from_xml_file(xml_file: str, tag_name: str) -> str:
    def delete_directory(folder_path: str) -> None:
    def get_files_differences(file1_path: str, file2_path: str) -> dict:

Git Utils -
    
    def clone_git_repo(repo_url: str, repo_dir: str, repo_branch: str) -> None:
    def get_branch_list(repo_url: str, repo_dir: str) -> list:

Pcap Analyzer Wireshark Utils - 
    
    def pcap_to_csv(pcap_file: str, csv_file: str, wireshark_path: str = None, csv_file_preferences: str = None, columns=None, display_filter: str = None, all_protocol: bool = True, tshark_cmd: str = None) -> str:
    def pcap_to_txt(pcap_file: str, txt_file: str, display_filter: str = None, decode_pref: dict = None, custom_pref: dict = None) -> str:
    def get_pcap_data(pcap_file: str, display_filter: str = None, decode_pref: dict = None, custom_pref: dict = None) -> str:
    def get_packet_header_count(pcap_csv_file: str, packet_header: str) -> int:

Linux Docker CLI - 

    def check_docker_service(ssh_conn: SSHClient = None, ip_address: str = None, username: str = None, password: str = None) -> bool:
    def build_docker_image(image_name: str, dockerfile_path: str, ssh_conn: SSHClient = None, ip_address: str = None, username: str = None, password: str = None) -> None:
    def stop_docker_container(container_name: str, ssh_conn: SSHClient = None, ip_address: str = None, username: str = None, password: str = None) -> None:
    def delete_docker_container(container_name: str, ssh_conn: SSHClient = None, ip_address: str = None, username: str = None, password: str = None) -> None:
    def delete_docker_image(image_name: str, ssh_conn: SSHClient = None, ip_address: str = None, username: str = None, password: str = None) -> None:
    def push_docker_image(image_name: str, ssh_conn: SSHClient = None, ip_address: str = None, username: str = None, password: str = None) -> None:

Linux Kubernetes CLI - 

    def run_command_within_pod(kube_config: str, command: str, pod_name: str, container_name: str = None, ssh_conn: SSHClient = None, ip_address: str = None, username: str = None, password: str = None) -> str:
    def copy_file_from_pod(kube_config: str, pod_name: str, container_name: str, src_path: str, dst_path: str, file_name: str, ssh_conn: SSHClient = None, ip_address: str = None, username: str = None, password: str = None) -> None:
    def scale_pod(kube_config: str, deployment_name: str, pod_count: int, ssh_conn: SSHClient = None, ip_address: str = None, username: str = None, password: str = None) -> str:
    def get_pod_logs(kube_config: str, pod_name: str, tail: int = None, ssh_conn: SSHClient = None, ip_address: str = None, username: str = None, password: str = None) -> str:
    def create_resource(kube_config: str, file: str, namespace: str = "default", ssh_conn: SSHClient = None, ip_address: str = None, username: str = None, password: str = None) -> None:
    def apply_resource(kube_config: str, file: str, ssh_conn: SSHClient = None, ip_address: str = None, username: str = None, password: str = None) -> None:
    def delete_resource(kube_config: str, resource_type: str, name: str, namespace: str = "default", force: bool = False, ssh_conn: SSHClient = None, ip_address: str = None, username: str = None, password: str = None) -> None:
    def get_resource_details_yaml(kube_config: str, resource_type: str, resource_name: str = "", namespace: str = "default", ssh_conn: SSHClient = None, ip_address: str = None, username: str = None, password: str = None) -> dict:

Linux Ubuntu CLI - 

    def create_ssh_conn(username: str, password: str, hostname: str = None, ip_address: str = None, pki: str = None, port: int = 22, sock: object = None) -> SSHClient:
    def close_ssh_conn(ssh_conn: SSHClient) -> None:
    def check_connection_status(ssh_conn: SSHClient) -> bool:
    def create_sftp_conn(ssh_conn: SSHClient) -> SFTPClient:
    def close_sftp_conn(sftp_conn: SFTPClient) -> None:
    def create_jumphost_conn(jumphost_public_ip: str, jumphost_private_ip: str, jumphost_username: str, jumphost_password: str, username: str, password: str, hostname: str = None, ip_address: str = None, jumphost_port: int = 22, port: int = 22) -> SSHClient:
    def start_tcpdump(pcap_file_path: str, ssh_conn: SSHClient = None, ip_address: str = None, username: str = None, password: str = None) -> None:
    def get_process_id_list(process_name: str, ssh_conn: SSHClient = None, ip_address: str = None, username: str = None, password: str = None) -> list:
    def soft_kill_process(process_id: str, ssh_conn: SSHClient = None, ip_address: str = None, username: str = None, password: str = None) -> None:
    def hard_kill_process(process_id: str, ssh_conn: SSHClient = None, ip_address: str = None, username: str = None, password: str = None) -> Non
    def copy_file_from_remote_to_local(remote_file_path: str, local_dir_path: str, ssh_conn: SSHClient = None, ip_address: str = None, username: str = None, password: str = None) -> None:
    def create_file(file_name: str, file_data: str, ssh_conn: SSHClient = None, ip_address: str = None, username: str = None, password: str = None) -> None:
    def get_file_content(file_name: str, ssh_conn: SSHClient = None, ip_address: str = None, username: str = None, password: str = None) -> str:
    def truncate_file(file: str, ssh_conn: SSHClient = None, ip_address: str = None, username: str = None, password: str = None) -> None:
    def find_file(dir_path: str, file_name: str, ssh_conn: SSHClient = None, ip_address: str = None, username: str = None, password: str = None) -> str:
    def change_file_mode(file_mode: str, file_name: str, ssh_conn: SSHClient = None, ip_address: str = None, username: str = None, password: str = None) -> str:
    def delete_file(file_path: str, ssh_conn: SSHClient = None, ip_address: str = None, username: str = None, password: str = None) -> None:
    def create_directory(dir_path: str, ssh_conn: SSHClient = None, ip_address: str = None, username: str = None, password: str = None) -> str:
    def compress_directory(folder_path: str, folder_name: str, ssh_conn: SSHClient = None, ip_address: str = None, username: str = None, password: str = None) -> None:
    def delete_directory(directory: str, ssh_conn: SSHClient = None, ip_address: str = None, username: str = None, password: str = None) -> None:
    def get_active_service_list(service_type: str, send_sudo: bool = False, ssh_conn: SSHClient = None, ip_address: str = None, username: str = None, password: str = None) -> list:
    def run_systemctl_command(option: str, unit: str, send_sudo: bool = False, ssh_conn: SSHClient = None, ip_address: str = None, username: str = None, password: str = None) -> None:
    def get_hostname(ssh_conn: SSHClient = None, ip_address: str = None, username: str = None, password: str = None) -> str:
    def set_hostname(hostname: str, ssh_conn: SSHClient = None, ip_address: str = None, username: str = None, password: str = None) -> str:
    def reboot_system(ssh_conn: SSHClient = None, ip_address: str = None, username: str = None, password: str = None) -> None:
