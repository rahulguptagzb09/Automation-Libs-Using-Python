import paramiko
from scp import SCPClient
from paramiko import SSHClient
from paramiko.sftp_client import SFTPClient


def create_ssh_conn(username: str, password: str, hostname: str = None,
                    ip_address: str = None, pki: str = None, port: int = 22,
                    sock: object = None) -> SSHClient:
    """
    This function is used to create SSH connection using Paramiko
    which requires hostname, username, password
    Arguments:
        username ('str'): username
        password ('str'): password
        hostname ('str'): hostname
        ip_address ('str'): IP address
        pki ('str'): PKI string
        port ('int'): port
        sock ('object'): socket
    Returns:
        ssh_conn ('SSHClient'): Paramiko SSHClient object
    """
    if ip_address:
        hostname = ip_address
    ssh_conn = paramiko.SSHClient()
    ssh_conn.load_system_host_keys()
    ssh_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connection_args = {
        "hostname": hostname,
        "username": username,
        "password": password,
        "sock": sock,
        "port": port
    }
    if pki:
        private_key = paramiko.RSAKey.from_private_key_file(pki)
        connection_args["pkey"] = private_key
    try:
        ssh_conn.connect(**connection_args)
    except Exception as e:
        raise ConnectionError(f"Exception while connecting to "
                              f"{hostname}") from e
    return ssh_conn


def close_ssh_conn(ssh_conn: SSHClient) -> None:
    """
    This function is used to close SSH connection
    Arguments:
        ssh_conn ('SSHClient'): Paramiko SSHClient object
    Returns:
        None
    """
    ssh_conn.close()


def check_connection_status(ssh_conn: SSHClient) -> bool:
    """
    This function is used to check the status of ssh connection
    Arguments:
        ssh_conn ('SSHClient'): Paramiko SSHClient object
    Returns:
        status ('bool'): connection status
    """
    try:
        return ssh_conn.get_transport().is_active()
    except Exception as error:
        print(
            f"Exception occurred while getting ssh connection status."
            f"\nDetailed exception: {error}"
        )
        return False


def create_sftp_conn(ssh_conn: SSHClient) -> SFTPClient:
    """
    This function is used to create SFTP connection
    Arguments:
        ssh_conn ('SSHClient'): Paramiko SSHClient object
    Returns:
        sftp_conn ('SFTPClient'): Paramiko SFTPClient object
    """
    try:
        sftp_conn = ssh_conn.open_sftp()
        return sftp_conn
    except Exception as error:
        raise ConnectionError("Exception occurred while opening sftp channel"
                              "") from error


def close_sftp_conn(sftp_conn: SFTPClient) -> None:
    """
    This function is used to close SFTP connection
    Arguments:
        sftp_conn ('SFTPClient'): Paramiko SFTPClient object
    Returns:
        None
    """
    sftp_conn.close()


def create_jumphost_conn(jumphost_public_ip: str, jumphost_private_ip: str,
                         jumphost_username: str, jumphost_password: str,
                         username: str, password: str, hostname: str = None,
                         ip_address: str = None, jumphost_port: int = 22,
                         port: int = 22) -> SSHClient:
    """
    This function is used to create SSH connection via jump host using 
    Paramiko connection which requires hostname, username, password
    Arguments:
        jumphost_public_ip ('str'): public IP of jump host
        jumphost_private_ip ('str'): private IP of jump host
        jumphost_username ('str'): username of jump host
        jumphost_password ('str'): password of jump host
        username ('str'): username of target device
        password ('str'): password of target device
        hostname ('str'): hostname of target device
        ip_address ('str'): ip address of target device
        jumphost_port ('int'): port of jump host
        port ('int'): port of target device
    Returns:
        target ('SSHClient'): Paramiko SSHClient object
    """
    if ip_address and not hostname:
        hostname = ip_address
    jumpbox = paramiko.SSHClient()
    jumpbox.load_system_host_keys()
    jumpbox.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    jumpbox.connect(jumphost_public_ip, username=jumphost_username,
                    password=jumphost_password)

    jumpbox_transport = jumpbox.get_transport()
    src_addr = (jumphost_private_ip, jumphost_port)
    dest_addr = (hostname, port)
    jumpbox_channel = jumpbox_transport.open_channel("direct-tcpip",
                                                     dest_addr, src_addr)
    target = paramiko.SSHClient()
    target.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    target.connect(hostname, username=username, password=password, sock=jumpbox_channel)
    return target


def start_tcpdump(pcap_file_path: str, ssh_conn: SSHClient = None,
                  ip_address: str = None,
                  username: str = None, password: str = None) -> None:
    """
    This function is used to run tcpdump command to capture and save data packets
    into a pcap file
    Arguments:
        pcap_file_path ('str'): pcap file name with path
        ssh_conn ('SSHClient'): Paramiko SSHClient object
        ip_address ('str'): ip_address
        username ('str'): username
        password ('str'): password
    Returns:
        None
    """
    if ssh_conn is None:
        ssh_conn = paramiko.SSHClient()
        ssh_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_conn.connect(hostname=ip_address, username=username,
                         password=password)
    ssh_conn.open_sftp()
    start_tcpdump_cmd = (f"echo {password} | sudo -S tcpdump -i "
                         f"any -w {pcap_file_path}")
    print('Command to start tcpdump : "%s"', start_tcpdump_cmd)
    try:
        ssh_conn.exec_command(start_tcpdump_cmd)  # nosec
    except Exception as err:
        print(f"Exception Error: {err}")


def get_process_id_list(process_name: str, ssh_conn: SSHClient = None,
                        ip_address: str = None,
                        username: str = None, password: str = None) -> list:
    """
    This function is used to get process ID list of a given process
    Arguments:
        process_name ('str'): name of the process
        ssh_conn ('SSHClient'): Paramiko SSHClient object
        ip_address ('str'): ip_address
        username ('str'): username
        password ('str'): password
    Returns:
        pid_lst ('list') process ID list
    """
    if ssh_conn is None:
        ssh_conn = paramiko.SSHClient()
        ssh_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_conn.connect(hostname=ip_address, username=username,
                         password=password)
    get_pid_list_cmd = f"ps -e | pgrep {process_name}"
    print('Command to get process ID list : "%s"', get_pid_list_cmd)
    try:
        _, stdout, _ = ssh_conn.exec_command(get_pid_list_cmd)  # nosec
        processes = stdout.readlines()
        pid_lst = [int(name.split('\n')[0]) for name in processes
                   if name and name.isdigit()]
        print('Process ID list : "%s"', pid_lst)
        ssh_conn.close()
        return pid_lst
    except Exception as err:
        print(f"Exception Error: {err}")
        return []


def soft_kill_process(process_id: str, ssh_conn: SSHClient = None,
                      ip_address: str = None,
                      username: str = None, password: str = None) -> None:
    """
    This function is used to stop a process using its process ID
    Arguments:
        process_id ('str'): process ID
        ssh_conn ('SSHClient'): Paramiko SSHClient object
        ip_address ('str'): ip_address
        username ('str'): username
        password ('str'): password
    Returns:
        None
    """
    if ssh_conn is None:
        ssh_conn = paramiko.SSHClient()
        ssh_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_conn.connect(hostname=ip_address, username=username,
                         password=password)
    kill_pid_cmd = f"echo {password} | sudo -S kill -2 {process_id}"
    print('Command to kill process ID : "%s"', kill_pid_cmd)
    try:
        ssh_conn.exec_command(kill_pid_cmd)  # nosec
    except Exception as err:
        print(f"Exception Error: {err}")


def hard_kill_process(process_id: str, ssh_conn: SSHClient = None,
                         ip_address: str = None,
                         username: str = None, password: str = None) -> None:
    """
    This function is used to forcefully terminate a process using its process ID
    Arguments:
        process_id ('str'): process ID
        ssh_conn ('SSHClient'): Paramiko SSHClient object
        ip_address ('str'): ip_address
        username ('str'): username
        password ('str'): password
    Returns:
        None
    """
    if ssh_conn is None:
        ssh_conn = paramiko.SSHClient()
        ssh_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_conn.connect(hostname=ip_address, username=username,
                         password=password)
    kill_pid_cmd = f"echo {password} | sudo -S kill -9 {process_id}"
    print('Command to kill process ID : "%s"', kill_pid_cmd)
    try:
        ssh_conn.exec_command(kill_pid_cmd)  # nosec
    except Exception as err:
        print(f"Exception Error: {err}")


def copy_file_from_remote_to_local(remote_file_path: str, local_dir_path: str,
                                   ssh_conn: SSHClient = None,
                                   ip_address: str = None,
                                   username: str = None,
                                   password: str = None) -> None:
    """
    This function is used to copy file from remote to local
    Arguments:
        remote_file_path ('str'): remote file path
        local_dir_path ('str'): local file path
        ssh_conn ('SSHClient'): Paramiko SSHClient object
        ip_address ('str'): ip_address
        username ('str'): username
        password ('str'): password
    Returns:
        None
    """
    try:
        if ssh_conn is None:
            ssh_conn = paramiko.SSHClient()
            ssh_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_conn.connect(hostname=ip_address, username=username,
                             password=password)
        sftp = ssh_conn.open_sftp()
        scp = SCPClient(ssh_conn.get_transport())
        print('Copying file from: {} to: {}'.format(remote_file_path,
                                                    local_dir_path))
        scp.get(remote_file_path, local_dir_path)
        sftp.close()
    except Exception as err:
        print(f"Exception Error: {err}")


def create_file(file_name: str, file_data: str, ssh_conn: SSHClient = None,
                ip_address: str = None,
                username: str = None, password: str = None) -> None:
    """
    This function is used to creates a new file with the given data
    Arguments:
        file_name ('str'): file name
        file_data ('str'): file data
        ssh_conn ('SSHClient'): Paramiko SSHClient object
        ip_address ('str'): ip_address
        username ('str'): username
        password ('str'): password
    Returns:
        None
    """
    if ssh_conn is None:
        ssh_conn = paramiko.SSHClient()
        ssh_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_conn.connect(hostname=ip_address, username=username,
                         password=password)
    if file_name is None or len(file_name) == 0:
        raise ValueError("Failed tpo create new file because "
                         "file_name is not provided")
    cmd = f"echo {file_data} > {file_name}"
    try:
        ssh_conn.exec_command(cmd)  # nosec
    except Exception as err:
        raise RuntimeError(
            f"Failed to create new file {file_name} with an "
            f"exception : {str(err)}"
        ) from err


def get_file_content(file_name: str, ssh_conn: SSHClient = None,
                     ip_address: str = None,
                     username: str = None, password: str = None) -> str:
    """
    This function is used to get the contents of a given file
    Arguments:
        file_name ('str'): file name path
        ssh_conn ('SSHClient'): Paramiko SSHClient object
        ip_address ('str'): ip_address
        username ('str'): username
        password ('str'): password
    Returns:
        output ('str'): output of the command
    """
    if ssh_conn is None:
        ssh_conn = paramiko.SSHClient()
        ssh_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_conn.connect(hostname=ip_address, username=username,
                         password=password)
    if file_name is not None:
        cmd = f"cat {file_name}"
    else:
        return ""
    try:
        _, stdout, _ = ssh_conn.exec_command(cmd)  # nosec
        output = ' '.join(stdout.readlines())
        return output
    except Exception as err:
        raise RuntimeError(
            f"Failed to print contents of file {file_name} with "
            f"an exception : {str(err)}"
        ) from err


def truncate_file(file: str, ssh_conn: SSHClient = None,
                  ip_address: str = None,
                  username: str = None, password: str = None) -> None:
    """
    This function is used to truncate or delete all content of a file
    Arguments:
        file ('str'): file path
        ssh_conn ('SSHClient'): Paramiko SSHClient object
        ip_address ('str'): ip_address
        username ('str'): username
        password ('str'): password
    Returns:
        None
    """
    if ssh_conn is None:
        ssh_conn = paramiko.SSHClient()
        ssh_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_conn.connect(hostname=ip_address, username=username,
                         password=password)
    cmd_trunc = f'echo {password} | sudo -S su -c "truncate -s 0 {file}"'
    try:
        ssh_conn.exec_command(cmd_trunc)  # nosec
    except Exception as TruncFileErr:
        print(f'Failed to truncate file {TruncFileErr}')


def find_file(dir_path: str, file_name: str, ssh_conn: SSHClient = None,
              ip_address: str = None,
              username: str = None, password: str = None) -> str:
    """
    This function is used to find a file in directory path
    Arguments:
        dir_path ('str'): directory path
        file_name ('str'): file name
        ssh_conn ('SSHClient'): Paramiko SSHClient object
        ip_address ('str'): ip_address
        username ('str'): username
        password ('str'): password
    Returns:
        output ('str'): output of the command
    """
    if ssh_conn is None:
        ssh_conn = paramiko.SSHClient()
        ssh_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_conn.connect(hostname=ip_address, username=username,
                         password=password)
    cmd = f"find {dir_path} -iname {file_name}"
    try:
        _, stdout, _ = ssh_conn.exec_command(cmd)  # nosec
        output = ' '.join(stdout.readlines())
        return output
    except Exception as err:
        raise RuntimeError(
            f"Failed to find file {file_name} with an exception : {str(err)}"
        ) from err


def change_file_mode(file_mode: str, file_name: str,
                     ssh_conn: SSHClient = None,
                     ip_address: str = None, username: str = None,
                     password: str = None) -> str:
    """
    This function is used to change the file mode (permissions) of a file
    Arguments:
        file_mode ('str'): new file mode value
        file_name ('str'): file name
        ssh_conn ('SSHClient'): Paramiko SSHClient object
        ip_address ('str'): ip_address
        username ('str'): username
        password ('str'): password
    Returns:
        output ('str'): output of the chmod command
    """
    if ssh_conn is None:
        ssh_conn = paramiko.SSHClient()
        ssh_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_conn.connect(hostname=ip_address, username=username,
                         password=password)
    cmd = f"chmod {file_mode} {file_name}"
    try:
        _, stdout, _ = ssh_conn.exec_command(cmd)  # nosec
        output = ' '.join(stdout.readlines())
        return output
    except Exception as err:
        raise RuntimeError(f"Failed to change mode of {file_name} "
                           f"with an exception : {str(err)}")


def delete_file(file_path: str, ssh_conn: SSHClient = None,
                ip_address: str = None,
                username: str = None, password: str = None) -> None:
    """
    This function is used to delete a file
    Arguments:
        file_path ('str'): file path
        ssh_conn ('SSHClient'): Paramiko SSHClient object
        ip_address ('str'): ip_address
        username ('str'): username
        password ('str'): password
    Returns:
        None
    """
    if ssh_conn is None:
        ssh_conn = paramiko.SSHClient()
        ssh_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_conn.connect(hostname=ip_address, username=username,
                         password=password)
    delete_file_cmd = "rm " + file_path
    print('Command to delete file : "%s"', delete_file_cmd)
    try:
        ssh_conn.exec_command(delete_file_cmd)  # nosec
    except Exception as err:
        print(f"Exception Error: {err}")


def create_directory(dir_path: str, ssh_conn: SSHClient = None,
                     ip_address: str = None,
                     username: str = None, password: str = None) -> str:
    """
    This function is used to creates a new directory
    Arguments:
        dir_path ('str'): directory path
        ssh_conn ('SSHClient'): Paramiko SSHClient object
        ip_address ('str'): ip_address
        username ('str'): username
        password ('str'): password
    Returns:
        output ('str'): output of the command
    """
    if ssh_conn is None:
        ssh_conn = paramiko.SSHClient()
        ssh_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_conn.connect(hostname=ip_address, username=username,
                         password=password)
    cmd = f"mkdir -p {dir_path}"
    try:
        _, stdout, _ = ssh_conn.exec_command(cmd)  # nosec
        output = ' '.join(stdout.readlines())
        return output
    except Exception as err:
        raise RuntimeError(
            f"Failed to create new dir {dir_path} with an exception : "
            f"{str(err)}"
        ) from err


def compress_directory(folder_path: str, folder_name: str,
                       ssh_conn: SSHClient = None,
                       ip_address: str = None, username: str = None,
                       password: str = None) -> None:
    """
    This function is used to compress folder to create a zip file
    Arguments:
        folder_path ('str'): directory path
        folder_name ('str'): folder name
        ssh_conn ('SSHClient'): Paramiko SSHClient object
        ip_address ('str'): ip_address
        username ('str'): username
        password ('str'): password
    Returns:
        None
    """
    if ssh_conn is None:
        ssh_conn = paramiko.SSHClient()
        ssh_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_conn.connect(hostname=ip_address, username=username,
                         password=password)
    zip_cmd = (f'echo {password} | sudo -S su -c "cd {folder_path}; '
               f'zip -r {folder_name}.zip {folder_name}"')
    try:
        ssh_conn.exec_command(zip_cmd)  # nosec
    except Exception as err:
        print(f"Exception Error: {err}")


def delete_directory(directory: str, ssh_conn: SSHClient = None,
                     ip_address: str = None,
                     username: str = None, password: str = None) -> None:
    """
    This function is used to delete a directory
    Arguments:
        directory ('str'): directory path
        ssh_conn ('SSHClient'): Paramiko SSHClient object
        ip_address ('str'): ip_address
        username ('str'): username
        password ('str'): password
    Returns:
        None
    """
    if ssh_conn is None:
        ssh_conn = paramiko.SSHClient()
        ssh_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_conn.connect(hostname=ip_address, username=username,
                         password=password)
    delete_folder_cmd = "rm -rf " + directory
    print('Command to delete directory : "%s"', delete_folder_cmd)
    try:
        ssh_conn.exec_command(delete_folder_cmd)  # nosec
    except Exception as err:
        print(f"Exception Error: {err}")


def get_active_service_list(service_type: str, send_sudo: bool = False,
                            ssh_conn: SSHClient = None,
                            ip_address: str = None, username: str = None,
                            password: str = None) -> list:
    """
    This function is used to get list of active running services
    Arguments:
        service_type ('str'): service type
        send_sudo ('bool'): flag whether the command should be run as sudo or not
        ssh_conn ('SSHClient'): Paramiko SSHClient object
        ip_address ('str'): ip_address
        username ('str'): username
        password ('str'): password
    Returns:
        active_service_list ('list'): active running services list
    """
    if ssh_conn is None:
        ssh_conn = paramiko.SSHClient()
        ssh_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_conn.connect(hostname=ip_address, username=username,
                         password=password)
    if send_sudo:
        sut_status_cmd = (f"echo {password} | systemctl "
                          f"--type=service | grep {service_type}")
    else:
        sut_status_cmd = f"systemctl --type=service | grep {service_type}"
    print(f'Command to get active running {service_type} '
          f'services list : {sut_status_cmd}')
    active_service_list = []
    try:
        _, stdout, _ = ssh_conn.exec_command(sut_status_cmd)  # nosec
        for line in iter(stdout.readline, ""):
            line = line.strip('\n')
            service_name = line.split()[0]
            active_service_list.append(service_name)
            print(f"Service {service_name} is running")
        print(f'{service_type} Active Running Service list :'
              f' "%s"', active_service_list)
        return active_service_list
    except Exception as err:
        print(f"Failed to retrieve running service list with "
              f"an exception : {err}")
        return []


def run_systemctl_command(option: str, unit: str, send_sudo: bool = False,
                          ssh_conn: SSHClient = None,
                          ip_address: str = None, username: str = None,
                          password: str = None) -> None:
    """
    This function is used to run systemctl command
    Arguments:
        option ('str'): systemctl command option
        unit ('str'): unit for which the systemctl command should run
        send_sudo ('bool'): flag whether the command should be run as sudo or not
        ssh_conn ('SSHClient'): Paramiko SSHClient object
        ip_address ('str'): ip_address
        username ('str'): username
        password ('str'): password
    Returns:
        None
    """
    if ssh_conn is None:
        ssh_conn = paramiko.SSHClient()
        ssh_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_conn.connect(hostname=ip_address, username=username,
                         password=password)
    if send_sudo:
        run_systemctl_cmd = f"echo {password} | systemctl {option} {unit}"
    else:
        run_systemctl_cmd = f"systemctl {option} {unit}"
    print('Command to run systemctl command : "%s"', run_systemctl_cmd)
    try:
        ssh_conn.exec_command(run_systemctl_cmd)  # nosec
    except Exception as err:
        raise RuntimeError(
            f"Failed to run systemctl {option} on {unit} with an "
            f"exception : {str(err)}"
        )


def get_hostname(ssh_conn: SSHClient = None, ip_address: str = None,
                 username: str = None, password: str = None) -> str:
    """
    This function is used to get hostname
    Arguments:
        ssh_conn ('SSHClient'): Paramiko SSHClient object
        ip_address ('str'): ip_address
        username ('str'): username
        password ('str'): password
    Returns:
        hostname ('str'): hostname
    """
    if ssh_conn is None:
        ssh_conn = paramiko.SSHClient()
        ssh_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_conn.connect(hostname=ip_address, username=username,
                         password=password)
    command = "hostname"
    try:
        _, stdout, _ = ssh_conn.exec_command(command, timeout=10)  # nosec
        hostname = ' '.join(stdout.readlines())
        return hostname
    except Exception as err:
        print(f"Host name not found : {str(err)}")
        raise


def set_hostname(hostname: str, ssh_conn: SSHClient = None,
                 ip_address: str = None,
                 username: str = None, password: str = None) -> str:
    """
    This function is used to set the hostname of the device
    Arguments:
        hostname ('str'): hostname
        ssh_conn ('SSHClient'): Paramiko SSHClient object
        ip_address ('str'): ip_address
        username ('str'): username
        password ('str'): password
    Returns:
        output ('str'): command output
    """
    if ssh_conn is None:
        ssh_conn = paramiko.SSHClient()
        ssh_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_conn.connect(hostname=ip_address, username=username,
                         password=password)
    command = f"hostnamectl set-hostname {hostname}"
    try:
        _, stdout, _ = ssh_conn.exec_command(command, timeout=10)  # nosec
        output = ' '.join(stdout.readlines())
        return output
    except Exception as err:
        print(f"Host name not set with {hostname} : {str(err)}")
        raise


def reboot_system(ssh_conn: SSHClient = None, ip_address: str = None,
                  username: str = None, password: str = None) -> None:
    """
    This function is used to reboot the system using reboot command
    Arguments:
        ssh_conn ('SSHClient'): Paramiko SSHClient object
        ip_address ('str'): ip_address
        username ('str'): username
        password ('str'): password
    Returns:
        None
    """
    if ssh_conn is None:
        ssh_conn = paramiko.SSHClient()
        ssh_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_conn.connect(hostname=ip_address, username=username,
                         password=password)
    cmd = "reboot"
    try:
        ssh_conn.exec_command(cmd)  # nosec
    except Exception as err:
        raise RuntimeError(f"Failed to reboot with an "
                           f"exception : {str(err)}")
