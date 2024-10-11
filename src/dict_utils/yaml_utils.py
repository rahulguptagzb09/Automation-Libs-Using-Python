import os
import pathlib
import ruamel.yaml
from src.dict_utils import dict_utils


def validate_yaml_schema(yaml_file: str, schema_dict: dict = None,
                         schema_json: str = None) -> dict:
    """
    This function is used to validate schema of input yaml file
    using input schema
    Arguments:
        yaml_file ('str'): input data dictionary to validate
        schema_dict ('dict'): input schema dictionary to validate
        schema_json ('str'): input schema json file to validate
    Returns:
        input_dict ('dict'): input data dictionary to validate
    """
    schema = ""
    if schema_json is not None:
        schema = dict_utils.load_json(schema_json)
    elif schema_dict is not None:
        schema = schema_dict

    if not schema:
        raise AssertionError(f"Schema is required {schema} "
                             f"and '{schema}' was provided")
    data = load_yaml(yaml_file)
    try:
        dict_utils.validate_data(data, schema)
    except Exception as e:
        raise AssertionError(f"{e} while validating the input: \n{yaml_file}")
    return data


def lowercase_keys_yaml(input_file: str, output_file: str,
                        ignore_keys: tuple = (), mapping: int = 2,
                        sequence: int = 4, offset: int = 2) -> None:
    """
    This function is used to transform all keys in yaml file to lower case
    Arguments:
        input_file ('str'): input yaml file
        output_file ('str'): output yaml file
        ignore_keys ('tuple'): ignore keys from being converted
        mapping ('int'): output file mapping
        sequence ('int'): output file sequence
        offset ('int'): output file offset
    Returns:
        None
    """
    data = load_yaml(input_file)
    if not output_file:
        raise AssertionError(f"output_file is required "
                             f"{output_file} and none was provided.")
    converted_data = dict_utils.lowercase_keys_dict(data, ignore_keys)
    yaml = ruamel.yaml.YAML()
    yaml.preserve_quotes = True
    yaml.explicit_start = True
    with open(output_file, "w") as converted_file:
        yaml.indent(mapping=mapping, sequence=sequence, offset=offset)
        yaml.dump(converted_data, converted_file)


def uppercase_keys_yaml(input_file: str, output_file: str,
                        ignore_keys: tuple = (), mapping: int = 2,
                        sequence: int = 4, offset: int = 2) -> None:
    """
    This function is used to transform all keys in yaml file to upper case
    Arguments:
        input_file ('str'): input yaml file
        output_file ('str'): output yaml file
        ignore_keys ('tuple'): ignore keys from being converted
        mapping ('int'): output file mapping
        sequence ('int'): output file sequence
        offset ('int'): output file offset
    Returns:
        None
    """
    data = load_yaml(input_file)
    if not output_file:
        raise AssertionError(f"output_file is required "
                             f"{output_file} and none was provided.")
    converted_data = dict_utils.uppercase_keys_dict(data, ignore_keys)
    yaml = ruamel.yaml.YAML()
    yaml.preserve_quotes = True
    yaml.explicit_start = True
    with open(output_file, "w") as converted_file:
        yaml.indent(mapping=mapping, sequence=sequence, offset=offset)
        yaml.dump(converted_data, converted_file)


def get_keys_list_from_yaml(input_file: str, key_path_list: list) -> list:
    """
    This function is used to find all keys in yaml file based on provided key path
    Arguments:
        input_file ('str'): input yaml file
        key_path_list ('list'): keys path as list
    Returns:
        keys_list ('list'): result list of item
    """
    data = load_yaml(input_file)
    keys_list = dict_utils.get_keys_list_from_dict(data, key_path_list)
    return keys_list


def load_yaml(yaml_file: str) -> dict:
    """
    This function is used to load data from yaml file
    Arguments:
        yaml_file ('str'): input yaml file
    Returns:
        data ('dict'): data dictionary
    """
    # Make sure yaml_file is readable and is a file
    if not os.path.isfile(yaml_file) or not os.access(yaml_file, os.R_OK):
        raise FileNotFoundError(f"'{yaml_file}' does not exists or "
                                "is unreadable")
    # Raise exception when file is empty
    if pathlib.Path(yaml_file).stat().st_size == 0:
        raise FileExistsError(f"Empty file provided. '{yaml_file}' "
                              "can not be empty")
    # Open yaml file
    with open(yaml_file, "r") as file_data:
        yaml_data = file_data.read()
    yaml = ruamel.yaml.YAML()
    yaml.preserve_quotes = True
    yaml.explicit_start = True
    data = yaml.load(yaml_data)
    if not data:
        raise AssertionError(f"data is required "
                             f"{data} and none was provided.")
    return data
