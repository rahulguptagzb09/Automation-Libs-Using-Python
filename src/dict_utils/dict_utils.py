import os
import re
import json
import pathlib
import jsonschema
from jsonschema import FormatChecker


def validate_dict_schema(input_dict: dict, schema_dict: dict = None,
                         schema_json: str = None) -> dict:
    """
    This function is used to validate schema of input dictionary using
    input schema
    Arguments:
        input_dict ('dict'): input data dictionary to validate
        schema_dict ('dict'): input schema dictionary to validate
        schema_json ('str'): input schema json file (path and file name)
    Returns:
        input_dict ('dict'): input data dictionary to validate
    """
    schema = ""
    if schema_json is not None:
        schema = load_json(schema_json)
    elif schema_dict is not None:
        schema = schema_dict

    if not schema:
        raise AssertionError(f"Schema is required {schema} "
                             f"and '{schema}' was provided")
    if not input_dict:
        raise AssertionError(f"input_dict is required "
                             f"{input_dict} and none was provided.")
    try:
        validate_data(input_dict, schema)
    except Exception as e:
        raise AssertionError(f"{e} while validating the input: \n{input_dict}")
    return input_dict


def lowercase_keys_dict(data: dict, ignore_keys: tuple = ()) -> dict:
    """
    This function is used to transform all keys in dictionary to lower case
    Arguments:
        data ('dict'): input data dictionary
        ignore_keys ('tuple'): ignore keys from being converted
    Returns:
        data ('dict'): output data dictionary
    """
    for k in list(data.keys()):
        nk = str(k)
        v = data[k]
        if k.isupper():
            nk = k.lower()
            data[nk] = v
            data.pop(k)
        if isinstance(v, dict) and k not in ignore_keys:
            data[nk] = lowercase_keys_dict(v, ignore_keys)
        if isinstance(v, list):
            for i in range(len(v)):
                if isinstance(v[i], dict):
                    v[i] = lowercase_keys_dict(v[i], ignore_keys)
    return data


def uppercase_keys_dict(data: dict, ignore_keys: tuple = ()) -> dict:
    """
    This function is used to transform all keys in dictionary to upper case
    Arguments:
        data ('dict'): input data dictionary
        ignore_keys ('tuple'): ignore keys from being converted
    Returns:
        data ('dict'): output data dictionary
    """
    for k in list(data.keys()):
        nk = str(k)
        v = data[k]
        if k.islower():
            nk = k.upper()
            data[nk] = v
            data.pop(k)
        if isinstance(v, dict) and k not in ignore_keys:
            data[nk] = uppercase_keys_dict(v, ignore_keys)
        if isinstance(v, list):
            for i in range(len(v)):
                if isinstance(v[i], dict):
                    v[i] = uppercase_keys_dict(v[i], ignore_keys)
    return data


def get_keys_list_from_dict(data: dict, key_path_list: list) -> list:
    """
    This function is used to find all keys in dictionary based on provided key path
    Arguments:
        data ('dict'): input data dictionary
        key_path_list ('list'): keys path as list
    Returns:
        keys_list ('list'): output list of keys
    """
    keys_list = []
    try:
        key_path = get_value_from_key_path_dict(data, key_path_list)
        for key in key_path:
            keys_list.append(key)
    except Exception as e:
        print(f"Key not found {e}")
    return keys_list


def get_value_from_key_path_dict(data: dict, key_path_list: list):
    """
    This function is used to find value in dictionary based on provided key path
    Arguments:
        data ('dict'): input data dictionary
        key_path_list ('list'): keys path as list
    Returns:
        key_path: key value
    """
    try:
        key_path_list = iter(key_path_list)
        key_path = data[next(key_path_list)]
        for item in key_path_list:
            key_path = key_path[item]
    except Exception as e:
        print(f"Key not found {e}")
        return None
    return key_path


def load_json(json_file: str) -> dict:
    """
    This function is used to load data from json file
    Arguments:
        json_file ('str'): json file path and file name
    Returns:
        data ('dict'): json data
    """
    if not os.access(json_file, os.R_OK):
        raise FileNotFoundError(f"'{json_file}' does not exists or "
                                "is unreadable")
    if pathlib.Path(json_file).is_file():
        with open(json_file) as file_schema:
            try:
                data = json.load(file_schema)
            except json.decoder.JSONDecodeError:
                raise ValueError(
                    f"Invalid JSON provided for json file: {json_file}"
                ) from None
        return data
    else:
        raise FileExistsError(f"JSON file {json_file} not found."
                              "\nProvide valid input file")


def validate_data(data: dict, schema: dict = None) -> dict:
    """
    This function is used to validate data against Json schema
    Arguments:
        data ('dict'): data in dictionary format
        schema ('dict'): Json schema to validate
    Returns:
        data ('dict'): validated data
    """
    if not schema:
        return data
    validator = jsonschema.Draft7Validator(schema,
                                           format_checker=FormatChecker())
    errors = validator.iter_errors(data)
    error_list = list(errors)
    if not error_list:
        return data
    detailed_err_list = []
    for error in error_list:
        error_path = list(error.absolute_path)
        if "not match any of the regexes: 'extra'" in error.message:
            message = re.sub(
                "(do|does) not match any of the regexes: 'extra'",
                "is not a valid key",
                error.message,
            )
        else:
            message = error.message
        detailed_err_list.append(f"{message} for the path: {error_path}")
    raise ValueError(
        f"Error validating data input dictionary. Errors are: "
        f"{detailed_err_list}"
    )
