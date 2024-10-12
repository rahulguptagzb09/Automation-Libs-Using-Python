from git import Repo


def clone_git_repo(repo_url: str, repo_dir: str, repo_branch: str) -> None:
    """
    This function is used to clone Git repository
    Arguments:
        repo_url ('str'): git repository URL
        repo_dir ('str'): git repository directory path
        repo_branch ('str'): git repository branch name
    Returns:
        None
    """
    repo = Repo.clone_from(repo_url, repo_dir)
    repo.git.checkout(repo_branch)


def get_branch_list(repo_url: str, repo_dir: str) -> list:
    """
    This function is used to get list of branch names of a Git repository
    Arguments:
        repo_url ('str'): git repository URL
        repo_dir ('str'): git repository directory path
    Returns:
        branch_list ('list'): list of branch names
    """
    branch_list = []
    repo = Repo.clone_from(repo_url, repo_dir)
    remote_refs = repo.remote().refs
    for item in remote_refs:
        branch_list.append(item.name)
    return branch_list
