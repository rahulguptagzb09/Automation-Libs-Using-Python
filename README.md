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
