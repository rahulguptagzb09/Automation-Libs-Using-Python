# For Testing YAML Functions

from src.dict_utils.yaml_utils import (
    validate_yaml_schema,
    lowercase_keys_yaml,
    uppercase_keys_yaml,
    get_keys_list_from_yaml
)

# For testing function to transform keys to lowercase in a YAML file
lowercase_keys_yaml("test_dict_keys_inp_file.yaml", "test_lower_out.yaml", ('key_5',))

# For testing function to transform keys to uppercase in a YAML file
uppercase_keys_yaml("test_dict_keys_inp_file.yaml", "test_upper_out.yaml")

# For testing function to validate schema for a YAML file
print(validate_yaml_schema("test_schema_inp_file.yaml", schema_json="test_schema_file.json"))

# For testing function to get keys from a YAML file
print(get_keys_list_from_yaml("test_schema_inp_file.yaml", ["main", "key1", "key2"]))
