# For Testing Dictionary (HashMaps) Functions

from src.dict_utils.dict_utils import (
    validate_dict_schema,
    lowercase_keys_dict,
    uppercase_keys_dict,
    get_keys_list_from_dict,
    get_value_from_key_path_dict
)

# For testing function to transform keys to uppercase in a dictionary
test_upper_dict = {
    "main": {
        "key1": {
            "key3": {
                "INT1": 1,
                "dict1": {
                    "dict2": {
                        "key4": "1.1.1.1"
                    }
                },
                "str1": "test",
                "list1": [
                    "aaa",
                    "bbb"
                ]
            },
        }
    }
}

print(uppercase_keys_dict(test_upper_dict, ('key3',)))

# For testing function to transform keys to lowercase in a dictionary
test_lower_dict = {
  'main': {'KEY1': {'KEY3': {
    'INT1': 1, 'DICT1': {'DICT2': {
      'KEY4': '1.1.1.1'}}, 'STR1': 'test', 'LIST1': ['aaa', 'bbb']}}}}

print(lowercase_keys_dict(test_lower_dict))

# For testing function to validate schema for a dictionary
test_schema = {
    "main": {
        "key1": {
            "key3": {
                "int1": 1,
                "dict1": {
                    "dict2": {
                        "key4": "1.1.1.1"
                    }
                },
                "str1": "test",
                "list1": [
                    "aaa",
                    "bbb"
                ]
            },
            "key2": {
                "int1": 1,
                "dict1": {
                    "dict2": {
                        "key4": "1.1.1.1"
                    }
                },
                "str1": "test",
                "list1": [
                    "aaa",
                    "bbb"
                ]
            }
        }
    }
}

print(validate_dict_schema(test_schema, schema_json="test_schema_file.json"))

# For testing function to get keys from a dictionary
print(get_keys_list_from_dict(test_schema, ["main", "key1", "key3"]))

# For testing function to get value using a path to a key in a dictionary
print(get_value_from_key_path_dict(test_schema, ["main", "key1", "key3"]))
