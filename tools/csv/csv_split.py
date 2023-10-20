import csv

'''Simple case where a CSV file has a header & related rows that are supposed to be 2 separate columns, but are concatenated into a single column by a tab
This can obviously be modified for flexibility
Occurred in instances of a provided CSV file exhibiting this issue'''

def split_single_column_CSV_by_char(input_file, output_file, char='\t'):
    # NOTE: doesn't account for header, assumes it is also a concatenation
    with open(input_file, 'r') as input_file:
        reader = csv.reader(input_file)

        with open(output_file, 'w', newline='') as output_file:
            writer = csv.writer(output_file)

            for row in reader:
                # print(row)
                if len(row) > 0:
                    # Split the first column by char to get two columns
                    col1, col2 = row[0].split(char)
                    writer.writerow([col1, col2])
