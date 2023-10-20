import os, sys
sys.path.append(os.path.join(os.path.dirname(__file__),"..", 'json'))
from json_helpers import write_python_data_to_file_as_json

def alternate_lines_to_dict(input_file, output_file, alt=None):
    '''Given a text file where lines alternate between a "key" and a "value",
    convert these to a python dict.\n
    This can handle empty lines between key and value lines\n
    'alt' will flip the reading pattern'''
    outputD = {}
    
    with open(input_file, 'r') as file:
        while True:
            if not alt:
                key = file.readline().strip()
                while key == "": # Skip empty lines to find a valid key
                    key = file.readline().strip()
                    if key == "":
                        if output_file:
                            write_python_data_to_file_as_json(outputD, output_file)
                        return outputD  # End of file reached
    
                value = file.readline().strip()
                while value == "": # Skip empty lines to find a valid value
                    value = file.readline().strip()
                    # CANADA STUFF
                    # if key in ('P', 'K', 'M', 'L', 'N'):
                    #     value = "Ontario"
                    # if key in ('G', 'J', 'H'):
                    #     value = "Quebec"
                    # if key == 'X' and not outputD.get(key, None):
                    #     value = ('Northwest Territories', 'Nunavut')
                    if value == "":
                        if output_file:
                            write_python_data_to_file_as_json(outputD, output_file)
                        return outputD  # End of file reached
                outputD[key] = value
            else:
                value = file.readline().strip()
                while value == "":
                    value = file.readline().strip()
                    if value == "":
                        if output_file:
                            write_python_data_to_file_as_json(outputD, output_file)
                        return outputD  # End of file reached
    
                key = file.readline().strip()
                while key == "":
                    key = file.readline().strip()
                    if key == "":
                        if output_file:
                            write_python_data_to_file_as_json(outputD, output_file)
                        return outputD  # End of file reached
                outputD[key] = value
