import os
import csv
import time
import shutil
import fnmatch
import difflib
import pandas as pd
from os import walk
from lxml import etree # nosec
from zipfile import ZipFile
from datetime import datetime
from filesplit.split import Split


def delete_files(path: str, days: int = 1, file_extension: str = "",
                     file_name_starting: str = "") -> list:
    """
    This function is used to delete old file based on modified date,
    extension and name prefix
    Arguments:
        path ('str'): Path or folder form where files needs to be deleted.
        days ('str'): Files having modified date older than mentioned days
                        will be deleted (default = 1). Example: 10
        file_extension ('str'): File extension (optional, can be "").
            Example: ".png"
        file_name_starting ('str'): File prefix (optional, can be "").
            Example: "Screen"
    Returns:
        deleted_file_names ('list'): list of deleted file names
    """
    deleted_file_names = []
    print("Path -", path)
    # Getting current datetime.
    now = time.time()
    # Number of files in the folder.
    file_count = 0
    # Number of files deleted from the folder.
    del_count = 0
    # Showing current datetime
    print('Now -', datetime.fromtimestamp(now))
    # Showing date before which files will be deleted
    print(days, "days ago -", datetime.fromtimestamp(now - days * 86400))

    # Getting all files in the folder
    for fi in os.listdir(path):
        # Getting full path including folder path and file name
        f = os.path.join(path, fi)
        # Increasing total number of files by 1
        file_count += 1
        # Getting modified datetime of each file.
        modified = datetime.fromtimestamp(os.stat(f).st_mtime)
        # Showing file number, file name and modified datetime of each file.
        print("File - ", file_count, fi, modified)
        # Checking if file is a file and not a folder, file extension is
        # matching or not
        # and file name starting is matching or not.
        if (os.path.isfile(f) and f.endswith(file_extension)
                and fi.startswith(file_name_starting)):
            # Checking if modified datetime of the file is before the
            # mentioned days or not.
            if os.stat(f).st_mtime < (now - (days * 24 * 60 * 60)):
                # Increasing the number of deleted files by 1
                del_count += 1
                # Showing deleted file number and file name
                print("Deleting -", del_count, f)
                # Command for deleting file
                os.remove(f)
                deleted_file_names.append(fi)

    # Showing Total number of files in all the mentioned folders and total
    # number of file deleted.
    print("Total Number of Files -", file_count,
          ", Total Number of Files Deleted -", del_count)
    return deleted_file_names


def split_file_by_lines(input_dir: str, output_dir: str,
                        number_of_lines: int = 1) -> None:
    """
    This function is used to split single into multiple files based on
    number of lines
    Arguments:
        input_dir ('str'): file that needs to split
        output_dir ('str'): Directory to store new files
        number_of_lines ('str'): number of lines
    Returns:
        None
    """
    split = Split(input_dir, output_dir)
    split.bylinecount(number_of_lines)


def find_lines_in_file_without_words(file_name: str, words: list) -> list:
    """
    This function is used to find lines without input words in a file
    Arguments:
        file_name ('str'): file name along with path.
            Put file name (if file is present in same folder as script) or
            file path (file is present in some other folder)
        words ('list'): list of words. Line will not contain these words.
            Example: ["200", "500"]
    Returns:
        out_lines ('list'):  list of lines
    """
    out_lines = []
    # Loading the file
    with open(file_name) as f:
        # Reading all lines
        lines = f.read().splitlines()
    f.close()
    # Checking the lines
    for line in lines:
        res = 1
        for word in words:
            if word in line:
                res = 0
        if res == 1:
            # Showing lines that does not contain the mentioned word.
            out_lines.append(str(line))
    return out_lines


def create_html(path: str, fields: list, data: dict) -> None:
    """
    This function is used to generate html report in form of rows and columns
    Arguments:
        path ('str'): html file path
        fields ('list'): list of field names
        data ('list'): data dictionary
    Returns:
        None
    """
    try:
        with open(path, 'a') as csvfile:
            writer = csv.DictWriter(csvfile, delimiter=',', fieldnames=fields)
            if csvfile.tell() == 0:
                writer.writeheader()
            writer.writerow(data)
        a = pd.read_csv(path)
        a.to_html(path, index=False, escape=False)
    except Exception as err:
        print(f"Exception Error: {err}")


def unzip_file(directory: str, zip_file_name: str) -> None:
    """
    This function is used to uncompress or unzip zip file
    Arguments:
        directory ('str'): directory path
        zip_file_name ('str'): folder name
    Returns:
        None
    """
    if not os.path.exists(directory):
        os.makedirs(directory)
    dst_zip_file = os.path.join(directory, zip_file_name)
    with ZipFile(dst_zip_file, 'r') as zip_extract:
        # extract in current directory
        zip_extract.extractall(directory)


def get_latest_file(find_file_str: str, directory: str) -> str:
    """
    This function is used to get the latest file name from directory
    Arguments:
        find_file_str ('str'): search string to get file name
        directory ('str'): directory path
    Returns:
        latest_file_name ('str'): file name
    """
    filtered_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if fnmatch.fnmatch(file, find_file_str):
                filtered_files.append(file)

    latest_log_file_name = max(filtered_files)
    return latest_log_file_name


def get_tag_value_from_xml_file(xml_file: str, tag_name: str) -> str:
    """
    This function is used to get the value of a specific tag in an XML file using lxml
    Arguments:
        xml_file ('str'): path to the XML file.
        tag_name ('str'): name of the tag to find.
    Returns:
        tag_value ('str'): value of the tag, or "" if the tag is not found.
    """
    try:
        # Parse the XML file
        tree = etree.parse(xml_file)  # nosec
        root = tree.getroot()
        xml_content = etree.tostring(root).decode()
        for line in xml_content.split('\n'):
            if tag_name in line:
                tag_value = line.split('>')[1].split('<')[0]
                return tag_value
    except Exception as e:
        print(f"Error finding tag value: {e}")
        return ""


def delete_directory(folder_path: str) -> None:
    """
    This function is used to delete directory or folder from local
    Arguments:
        folder_path ('str'): path to the XML file.
    Returns:
        None
    """
    for (dirpath, dirnames, filenames) in walk(folder_path):
        try:
            shutil.rmtree(dirpath)
            print(f"Deleted folder path : {dirpath}")
        except Exception as e:
            print(f"Error while deleting folder : {e}")


def get_files_differences(file1_path: str, file2_path: str) -> dict:
    """
    This function is used to get the line-by-line difference between two files.
    Parameters:
        file1_path ('str'): path of first file
        file2_path ('str'): path of second file
    Returns:
        diff_dict ('dict'): dict having list of tuples representing the differences between files
    """
    diff_dict = {}
    try:
        with open(file1_path, 'r') as file1, open(file2_path, 'r') as file2:
            file1_lines = file1.readlines()
            file2_lines = file2.readlines()
            print("length of file: %s, %s lines", file1_path, len(file1_lines))
            print("length of file: %s, %s lines", file2_path, len(file2_lines))

        differ = difflib.Differ()
        diff = differ.compare(file1_lines, file2_lines)
        file1_name = os.path.basename(file1_path)
        file2_name = os.path.basename(file2_path)
        diff_dict[file1_name] = ""
        diff_dict[file2_name] = ""
        line_num = 0
        for line in list(diff):
            if line[0] == '-':
                line_num = line_num + 1
                diff_dict[file1_name] = (diff_dict[file1_name] + f" {line_num} - {line}")
            elif line[0] == '+':
                diff_dict[file2_name] = (diff_dict[file2_name] + f" {line_num} - {line}")
            else:
                line_num = line_num + 1

    except Exception as e:
        print(f"Error while comparing files : {e}")
        return {}
    return diff_dict
