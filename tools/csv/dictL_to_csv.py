import csv

def conv_list_of_d_to_csv(input, output_file):
    '''Convert a list of dictionaries to a CSV file.\n
    Headers are gathered from the dictionary keys, which should all be uniform'''
    with open(output_file, 'w', encoding='utf-8-sig', newline='') as out:
        headers = list(input[0].keys())
        writer = csv.DictWriter(out, fieldnames=headers)
        writer.writeheader()
    
        for i, row in enumerate(input, 1):
            try:
                writer.writerow(row)
            except ValueError as e:
                print(f"Error in data row {i}: {e}")

def generate_targets_from_csv(input_file, expected_headers):
    '''Create a list of dictionaries from a CSV file.\n
    A list of headers must be provided to ensure they match dictionary keys'''
    with open(input_file, 'r', encoding='utf-8-sig') as input:
        output = []
        reader = csv.DictReader(input)
        header = set(reader.fieldnames)
        if header != set(expected_headers):
            print("Header Mismatch!")
            exit(1)
        for row in reader:
            row_data = {}
            for field_name in expected_headers:
                row_data[field_name] = row.get(field_name)
            output.append(row_data)
    return output
