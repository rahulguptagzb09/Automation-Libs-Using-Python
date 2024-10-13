import os
import csv
import pyshark
import platform
import subprocess  # nosec


def pcap_to_csv(pcap_file: str, csv_file: str, wireshark_path: str = None,
                csv_file_preferences: str = None, columns=None,
                display_filter: str = None, all_protocol: bool = True,
                tshark_cmd: str = None) -> str:
    """
    This function is used export the details of a pcap file into csv file
    Arguments:
        pcap_file ('str'): pcap file name along with path
        csv_file ('str'): csv file name
        wireshark_path ('str'): wireshark path
        csv_file_preferences ('str'): protocol preferences
        columns ('str'): columns
        display_filter ('str'): display_filter
        all_protocol ('bool'): all_protocol
        tshark_cmd ('str'): tshark_cmd
    Returns:
        csv_file ('str'): csv file path along with file name
    """
    if columns is None:
        columns = []
    if wireshark_path is None:
        server_os = platform.system
        if server_os == "Windows":
            wireshark_path = "C:\\Program Files\\Wireshark"
        else:
            wireshark_path = "/usr/local/bin/"
    try:
        os.chdir(wireshark_path)
    except Exception as PathError:
        print(f"Exception while changing the directory to {wireshark_path} "
              f"from {PathError}")
    if tshark_cmd is not None:
        try:
            subprocess.getoutput(tshark_cmd)
        except Exception as CommandError:
            print(f"Error caught while running the command {tshark_cmd} "
                  f"from {CommandError}")
        return csv_file
    if csv_file_preferences is None:
        csv_file_preferences = ("-o nas-5gs.null_decipher:TRUE -d "
                                "tcp.port==7777,http2")
    start_command = f"tshark {csv_file_preferences} -r "
    if columns is None:
        columns = ["frame.time_delta", "ip.src", "ip.dst", "_ws.col.Info"]
    columns_cmd = ""
    for column in columns:
        columns_cmd += "-e " + column
    all_protocol_cmd = ""
    if all_protocol:
        all_protocol_cmd = "--enable-protocol all"
    display_filter_cmd = ""
    if display_filter is not None:
        display_filter_cmd = "-f " + display_filter
    tshark_command = (f"{display_filter_cmd} -T fields -E header=y -E "
                      f"separator=, -E quote=d "
                      f"-E occurrence=f {columns_cmd} -E header=n "
                      f"{all_protocol_cmd} > ")
    command = f"{start_command}{pcap_file}{tshark_command}{csv_file}"
    try:
        subprocess.getoutput(command)
    except Exception as CommandError:
        print(f"Error caught while running the command {command} "
              f"from {CommandError}")
    return csv_file


def pcap_to_txt(pcap_file: str, txt_file: str, display_filter: str = None,
                decode_pref: dict = None,
                custom_pref: dict = None) -> str:
    """
    This function is used write a particular packet data in text file
    Arguments:
        pcap_file ('str'): pcap file name along with the file path
        txt_file ('str'): text file which contains the packet information
        display_filter ('str'): protocol to display_filter the particular packet
        decode_pref ('dict'): decode preference for pcap
        custom_pref ('dict'): custom preferences set for pcap
    Returns:
        txt_file ('str'): text file which contains the packet information
    """
    if decode_pref is None:
        decode_pref = {"tcp.port==7777": "http2"}
    if custom_pref is None:
        custom_pref = {"-o": "nas-5gs.null_decipher:true"}
    if display_filter is None:
        cap = pyshark.FileCapture(pcap_file, decode_as=decode_pref,
                                  custom_parameters=custom_pref)
    else:
        cap = pyshark.FileCapture(pcap_file, display_filter=display_filter,
                                  decode_as=decode_pref,
                                  custom_parameters=custom_pref)
    with open(txt_file, "a+") as txt_file_obj:
        for pkt in cap:
            pkt = str(pkt)
            txt_file_obj.write(pkt)
    cap.close()
    return txt_file


def get_pcap_data(pcap_file: str, display_filter: str = None,
                  decode_pref: dict = None,
                  custom_pref: dict = None) -> str:
    """
    This function is used get packet data from a pcap file
    Arguments:
        pcap_file ('str'): pcap file name along with the file path
        display_filter ('str'): protocol to display filter the particular packet
        decode_pref ('dict'): decode preference for pcap
        custom_pref ('dict'): custom preferences set for pcap
    Returns:
        data ('str'): packet data
    """
    data = ""
    if decode_pref is None:
        decode_pref = {"tcp.port==7777": "http2"}
    if custom_pref is None:
        custom_pref = {"-o": "nas-5gs.null_decipher:true"}
    if display_filter is None:
        cap = pyshark.FileCapture(pcap_file, decode_as=decode_pref,
                                  custom_parameters=custom_pref)
    else:
        cap = pyshark.FileCapture(pcap_file, display_filter=display_filter,
                                  decode_as=decode_pref,
                                  custom_parameters=custom_pref)
    for pkt in cap:
        data += str(pkt)
    cap.close()
    return data


def get_packet_header_count(pcap_csv_file: str, packet_header: str) -> int:
    """
    This function is used get count of packet header
    Arguments:
        pcap_csv_file ('str'): csv file path along with csv file name
        packet_header ('str'): packet header name.
            Example: "PDU session establishment request"
    Returns:
        counter ('int'): count of packet header
    """
    with open(pcap_csv_file, "r") as pcap_file:
        csvreader = csv.reader(pcap_file)
        rows = []
        for row in csvreader:
            rows.append(row)
    if not packet_header or not isinstance(packet_header, str):
        raise AttributeError(f"Name {packet_header} is not valid")
    counter = 0
    for row_data in rows:
        for info_data in row_data:
            if packet_header in info_data:
                counter = counter + 1
    return counter
