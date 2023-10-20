import json

def write_python_data_to_file_as_json(data, output_file):
    with open(output_file, 'w') as file:
        file.write(json.dumps(data))
