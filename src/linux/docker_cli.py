import paramiko
from paramiko.client import SSHClient
from paramiko.ssh_exception import SSHException


def check_docker_service(ssh_conn: SSHClient = None, ip_address: str = None,
                         username: str = None, password: str = None) -> bool:
    """
    This function is used to check the docker service
    Arguments:
        ssh_conn ('SSHClient'): Paramiko SSHClient object
        ip_address ('str'): ip_address
        username ('str'): username
        password ('str'): password
    Returns:
        output ('bool'): True if docker service is present
    """
    if ssh_conn is None:
        ssh_conn = paramiko.SSHClient()
        ssh_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_conn.connect(hostname=ip_address, username=username,
                         password=password)
    cmd = "systemctl | grep docker.service"
    try:
        _, stdout, _ = ssh_conn.exec_command(cmd)  # nosec
        output = ' '.join(stdout.readlines())
    except Exception as output:
        raise SSHException(f"Failed to run command: {cmd} with error: {output}")
    return "docker.service" in output


def build_docker_image(image_name: str, dockerfile_path: str,
                       ssh_conn: SSHClient = None, ip_address: str = None,
                       username: str = None, password: str = None) -> None:
    """
    This function is used to build a docker image
    Arguments:
        image_name ('str'): Docker image name
        dockerfile_path ('str'): Docker file path
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
    cmd = f"docker build -t {image_name} -f {dockerfile_path}"
    ssh_conn.exec_command(cmd)  # nosec


def stop_docker_container(container_name: str, ssh_conn: SSHClient = None,
                          ip_address: str = None, username: str = None,
                          password: str = None) -> None:
    """
    This function is used to stop a Docker container
    Arguments:
        container_name ('str'): Docker container name
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
    cmd = f"docker stop {container_name}"
    ssh_conn.exec_command(cmd)  # nosec


def delete_docker_container(container_name: str, ssh_conn: SSHClient = None,
                            ip_address: str = None, username: str = None,
                            password: str = None) -> None:
    """
    This function is used to delete a Docker container
    Arguments:
        container_name ('str'): Docker container name
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
    cmd = f"docker rm -f {container_name}"
    ssh_conn.exec_command(cmd)  # nosec


def delete_docker_image(image_name: str, ssh_conn: SSHClient = None,
                        ip_address: str = None, username: str = None,
                        password: str = None) -> None:
    """
    This function is used to delete a Docker image
    Arguments:
        image_name ('str'): Docker image name
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
    cmd = f"docker rmi -f {image_name}"
    ssh_conn.exec_command(cmd)  # nosec


def push_docker_image(image_name: str, ssh_conn: SSHClient = None,
                      ip_address: str = None, username: str = None,
                      password: str = None) -> None:
    """
    This function is used to push a Docker image to artifactory
    Arguments:
        image_name ('str'): Docker image name
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
    cmd = f"docker push {image_name}"
    ssh_conn.exec_command(cmd)  # nosec
