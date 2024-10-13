import yaml
import paramiko
from paramiko.client import SSHClient
from paramiko.ssh_exception import SSHException


def run_command_within_pod(kube_config: str, command: str, pod_name: str,
                           container_name: str = None,
                           ssh_conn: SSHClient = None,
                           ip_address: str = None, username: str = None,
                           password: str = None) -> str:
    """
    This function is used to run ssh cli command within pod or one of the pod container
    Arguments:
        kube_config ('str'): location of kubeconfig file
        command ('str'): command
        pod_name ('str'): pod name
        container_name ('str'): container name
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
    if container_name is None or container_name == "":
        cmd = (f"export KUBECONFIG={kube_config}; kubectl exec -it "
               f"{pod_name} -- bash -c '{command}'")
    else:
        cmd = (f"export KUBECONFIG={kube_config}; kubectl exec -it "
               f"{pod_name} -c "
               f"{container_name} -- bash -c '{command}'")
    try:
        _, stdout, _ = ssh_conn.exec_command(cmd)  # nosec
        output = ' '.join(stdout.readlines())
        return output
    except Exception as err:
        print(f'Error while running command using kubectl : {err}')


def copy_file_from_pod(kube_config: str, pod_name: str,
                       container_name: str, src_path: str,
                       dst_path: str, file_name: str,
                       ssh_conn: SSHClient = None,
                       ip_address: str = None, username: str = None,
                       password: str = None) -> None:
    """
    This function is used to copy a file from pod or pod container
    Arguments:
        kube_config ('str'): location of kubeconfig file
        pod_name ('str'): pod name
        container_name ('str'): container name
        src_path ('str'): source file path
        dst_path ('str'): destination file path
        file_name ('str'): file name
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
    if container_name is None or container_name == "":
        copy_cmd = (f"export KUBECONFIG={kube_config}; kubectl cp "
                    f"{pod_name}:{src_path}{file_name} "
                    f"{dst_path}/{file_name}")
    else:
        copy_cmd = (f"export KUBECONFIG={kube_config}; kubectl cp "
                    f"{pod_name}:{src_path}{file_name}"
                    f" -c {container_name} {dst_path}/{file_name}")
    try:
        ssh_conn.exec_command(copy_cmd)  # nosec
    except Exception as err:
        print(f'Error while running copying file from pod '
              f': "{copy_cmd}" Error: {err}')


def scale_pod(kube_config: str, deployment_name: str, pods_count: int,
              ssh_conn: SSHClient = None, ip_address: str = None,
              username: str = None, password: str = None) -> str:
    """
    This function is used to scale a pod
    Arguments:
        kube_config ('str'): location of kubeconfig file
        deployment_name ('str'): deployment name
        pods_count ('int'): number of pods to be created
        ssh_conn ('SSHClient'): Paramiko SSHClient object
        ip_address ('str'): ip_address
        username ('str'): username
        password ('str'): password
    Returns:
        scaling_status ('str'): scaling status of the pod
    """
    if ssh_conn is None:
        ssh_conn = paramiko.SSHClient()
        ssh_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_conn.connect(hostname=ip_address, username=username,
                         password=password)
    cmd = (f"export KUBECONFIG={kube_config}; kubectl scale "
           f"deployment {deployment_name} "
           f"--replicas={pods_count}")
    try:
        _, stdout, _ = ssh_conn.exec_command(cmd)  # nosec
        scaling_status = ' '.join(stdout.readlines())
    except Exception as err:
        raise RuntimeError(f"Failed to scale the pod with error: "
                           f"{str(err)}") from err
    return scaling_status


def get_pod_logs(kube_config: str, pod_name: str, tail: int = None,
                 ssh_conn: SSHClient = None, ip_address: str = None,
                 username: str = None, password: str = None) -> str:
    """
    This function is used to get pod logs
    Arguments:
        kube_config ('str'): location of kubeconfig file
        pod_name ('str'): pod name
        tail ('int'): tail length
        ssh_conn ('SSHClient'): Paramiko SSHClient object
        ip_address ('str'): ip_address
        username ('str'): username
        password ('str'): password
    Returns:
        output ('str'): Output of pod logs
    """
    if ssh_conn is None:
        ssh_conn = paramiko.SSHClient()
        ssh_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_conn.connect(hostname=ip_address, username=username,
                         password=password)
    if tail:
        cmd = (f"export KUBECONFIG={kube_config}; kubectl "
               f"logs {pod_name} --tail={tail}")
    else:
        cmd = (f"export KUBECONFIG={kube_config}; kubectl "
               f"logs {pod_name}")
    try:
        _, stdout, _ = ssh_conn.exec_command(cmd)  # nosec
        output = ' '.join(stdout.readlines())
    except Exception as err:
        raise RuntimeError(f"Failed to get pod logs with an exception: "
                           f"{str(err)}") from err
    return output


def create_resource(kube_config: str, file: str, namespace: str = "default",
                    ssh_conn: SSHClient = None,
                    ip_address: str = None, username: str = None,
                    password: str = None) -> None:
    """
    This function is used to create a resource using kubectl create command
    Arguments:
        kube_config ('str'): location of kubeconfig file
        file ('str'): resource YAML file path
        namespace ('str'): namespace
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
    cmd = (f"export KUBECONFIG={kube_config}; kubectl create -f "
           f"{file} -n {namespace}")
    _, stdout, _ = ssh_conn.exec_command(cmd)  # nosec
    output = ' '.join(stdout.readlines())
    if " created" not in output:
        raise RuntimeError(f"Failed to create resource: {output}")


def apply_resource(kube_config: str, file: str,
                   ssh_conn: SSHClient = None, ip_address: str = None,
                   username: str = None, password: str = None) -> None:
    """
    This function is used to create a resource using kubectl apply command
    Arguments:
        kube_config ('str'): location of kubeconfig file
        file ('str'): resource YAML file path
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
    cmd = f"export KUBECONFIG={kube_config}; kubectl apply -f {file}"
    _, stdout, _ = ssh_conn.exec_command(cmd)  # nosec
    out = ' '.join(stdout.readlines())
    if not any(x in out for x in [" created", " unchanged", " configured"]):
        raise RuntimeError(f"Failed to apply resource: {out}")


def delete_resource(kube_config: str, resource_type: str, name: str,
                    namespace: str = "default", force: bool = False,
                    ssh_conn: SSHClient = None,
                    ip_address: str = None, username: str = None,
                    password: str = None) -> None:
    """
    This function is used to delete a resource
    Arguments:
        kube_config ('str'): location of kubeconfig file
        resource_type ('str'): resource type
        name ('str'): resource name
        namespace ('str'): namespace
        force ('bool'): forcefully delete a resource
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
    cmd = (f"export KUBECONFIG={kube_config}; kubectl delete "
           f"{resource_type} {name} -n {namespace}")
    _msg = f' "{name}" deleted'
    if force:
        cmd = f"{cmd} --force"
        _msg = f' "{name}" force deleted'
    _, stdout, _ = ssh_conn.exec_command(cmd)  # nosec
    output = ' '.join(stdout.readlines())
    if _msg not in output:
        raise RuntimeError(f"Failed to delete {resource_type} {name} "
                           f"with error: {output}")


def get_resource_details_yaml(kube_config: str, resource_type: str,
                              resource_name: str = "", namespace: str = "default",
                              ssh_conn: SSHClient = None,
                              ip_address: str = None, username: str = None,
                              password: str = None) -> dict:
    """
    This function is used to get resource details in YAML form
    Arguments:
        kube_config ('str'): location of kubeconfig file
        resource_type ('str'): resource type
        namespace ('str'): namespace
        resource_name ('str'): resource name
        ssh_conn ('SSHClient'): Paramiko SSHClient object
        ip_address ('str'): ip_address
        username ('str'): username
        password ('str'): password
    Returns:
        output ('dict'): output of command in dict format
    """
    if ssh_conn is None:
        ssh_conn = paramiko.SSHClient()
        ssh_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_conn.connect(hostname=ip_address, username=username,
                         password=password)
    cmd = (f"export KUBECONFIG={kube_config}; kubectl get "
           f"{resource_type} -n {namespace} "
           f"-o yaml {resource_name}")
    try:
        _, stdout, _ = ssh_conn.exec_command(cmd)  # nosec
        out = ' '.join(stdout.readlines())
    except SSHException as err:
        raise RuntimeError(f"Failed to get resource details with error : "
                           f"{str(err)}") from err
    return yaml.safe_load(out)
