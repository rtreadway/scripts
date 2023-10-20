import csv

def trim_csv_up_to_n(input_file, output_file, n):
    '''Trim a CSV file up to row "n" and output result to a new file'''
    with open(input_file, 'r') as infile:
        reader = csv.reader(infile)
        rows = list(reader)
    with open(output_file, 'w', newline='') as outfile:
        writer = csv.writer(outfile)
        writer.writerow(rows[0]) # header
        # Write the rows after the trimmed ones
        writer.writerows(rows[n+1:])

def trim_csv_from_to(input_file, output_file, from_x, to_y):
    '''Trim a CSV from from row "x" to "y" (y exclusive) and output to a new file'''
    with open(input_file, 'r') as infile:
        reader = csv.reader(infile)
        rows = list(reader)
    with open(output_file, 'w', newline='') as outfile:
        writer = csv.writer(outfile)
        writer.writerow(rows[0]) # header
        writer.writerows(rows[from_x:to_y])
