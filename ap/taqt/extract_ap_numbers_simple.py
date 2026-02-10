#!/usr/bin/env python3
"""
Simple script to extract AP numbers from TAQT log files.
Usage: python extract_ap_numbers_simple.py [-n N] [-o OUTPUT_FILE]
Where N is the number of AP numbers to omit from the end of each file (default: 1)
"""

import os
import re
import glob
import sys
import argparse
import json
import itertools
from typing import List

def extract_ap_numbers(file_path: str, regex_pattern: str, omit_last_n: int = 1) -> tuple[List[str], List[str]]:
    """Extract AP numbers from a log file using the provided regex pattern, omitting the last N entries.
    
    Returns:
        tuple: (collected_ap_numbers, omitted_ap_numbers)
    """
    ap_numbers = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                # Use the provided regex pattern to find AP numbers
                match = re.search(regex_pattern, line)
                if match:
                    # Use the first capture group (or the whole match if no groups)
                    ap_number = match.group(1) if match.groups() else match.group(0)
                    ap_numbers.append(ap_number)
    
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return [], []
    
    # Split into collected and omitted
    if omit_last_n > 0 and len(ap_numbers) > omit_last_n:
        collected = ap_numbers[:-omit_last_n]
        omitted = ap_numbers[-omit_last_n:]
    elif omit_last_n > 0 and len(ap_numbers) <= omit_last_n:
        collected = []  # All entries would be omitted
        omitted = ap_numbers
    else:
        collected = ap_numbers
        omitted = []
    
    return collected, omitted

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(
        description='Extract AP numbers from TAQT log files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Omit last 1 AP number from each file (default)
  %(prog)s -n 3               # Omit last 3 AP numbers from each file
  %(prog)s -n 0               # Don't omit any AP numbers
  %(prog)s -o output.txt      # Save to custom output file
  %(prog)s -n 2 -o results.txt # Omit last 2 and save to results.txt
  %(prog)s -d /path/to/logs   # Search for log files in specific directory
  %(prog)s -r "ID: ([0-9]+)"  # Use custom regex pattern
  %(prog)s -d ./data -r "User ([A-Z0-9]+)" -n 0 # Custom dir, regex, no omit
  %(prog)s -f json -o data.json # Save as JSON format
  %(prog)s -f text -o data.txt  # Save as text format (default)
  %(prog)s -c 3 -o output.txt # Split into 3 text files: output_1.txt, output_2.txt, output_3.txt
  %(prog)s -c 2 -f json -o data.json # Split into JSON object with keys "1" and "2"
        """
    )
    
    parser.add_argument(
        '-n', '--omit-last',
        type=int,
        default=1,
        metavar='N',
        help='Number of AP numbers to omit from the end of each file (default: %(default)s)'
    )
    
    parser.add_argument(
        '-o', '--output',
        type=str,
        default='extracted_ap_numbers.txt',
        metavar='FILE',
        help='Output file name (default: %(default)s)'
    )
    
    parser.add_argument(
        '-d', '--directory',
        type=str,
        default='.',
        metavar='DIR',
        help='Directory to search for log files (default: current directory and logs subdirectory)'
    )
    
    parser.add_argument(
        '-r', '--regex',
        type=str,
        default=r'AP number from student page\.\.([A-Z0-9]{8})',
        metavar='PATTERN',
        help='Regex pattern to extract AP numbers. Use capture groups to specify what to extract (default: %(default)s)'
    )
    
    parser.add_argument(
        '-f', '--format',
        type=str,
        choices=['text', 'json'],
        default='text',
        help='Output format: text (one per line) or json (JSON list) (default: %(default)s)'
    )
    
    parser.add_argument(
        '-c', '--chunks',
        type=int,
        default=1,
        metavar='N',
        help='Number of chunks to split the output into (default: %(default)s). For text: creates separate files. For JSON: creates object with numbered keys.'
    )
    
    args = parser.parse_args()
    omit_last_n = args.omit_last
    output_file = args.output
    directory = args.directory
    regex_pattern = args.regex
    output_format = args.format
    num_chunks = args.chunks
    
    # Validate arguments
    if omit_last_n < 0:
        parser.error("Number of AP numbers to omit cannot be negative")
    
    if num_chunks < 1:
        parser.error("Number of chunks must be at least 1")
    
    # Validate regex pattern
    try:
        re.compile(regex_pattern)
    except re.error as e:
        parser.error(f"Invalid regex pattern: {e}")
    
    # Validate directory
    if not os.path.exists(directory):
        parser.error(f"Directory does not exist: {directory}")
    if not os.path.isdir(directory):
        parser.error(f"Path is not a directory: {directory}")
    
    # Find all log files in the specified directory and its logs subdirectory
    log_files = []
    patterns = [
        os.path.join(directory, "*.log"),
        os.path.join(directory, "logs", "*.log")
    ]
    
    for pattern in patterns:
        log_files.extend(glob.glob(pattern))
    
    if not log_files:
        print(f"No log files found in directory: {directory}")
        sys.exit(1)
    
    log_files.sort()
    print(f"Processing {len(log_files)} log files from '{directory}', omitting last {omit_last_n} AP number(s) from each file:")
    print(f"Using regex pattern: {regex_pattern}\n")
    
    all_ap_numbers = []
    all_omitted_numbers = []
    files_processed = 0
    
    for log_file in log_files:
        file_name = os.path.basename(log_file)
        collected_ap_numbers, omitted_ap_numbers = extract_ap_numbers(log_file, regex_pattern, omit_last_n)
        
        files_processed += 1
        
        if collected_ap_numbers or omitted_ap_numbers:
            print(f"{file_name}: {len(collected_ap_numbers)} AP numbers collected, {len(omitted_ap_numbers)} omitted")
            all_ap_numbers.extend(collected_ap_numbers)
            all_omitted_numbers.extend(omitted_ap_numbers)
        else:
            print(f"{file_name}: No AP numbers found")
    
    # Save collected numbers to file
    def chunk_list(lst, n):
        """Split a list into n roughly equal chunks using itertools"""
        if n <= 0 or not lst:
            return [lst] if lst else []
        
        if n >= len(lst):
            # If we want more chunks than items, return each item as its own chunk
            return [[item] for item in lst]
        
        # Calculate chunk size - distribute items as evenly as possible
        chunk_size = len(lst) // n
        remainder = len(lst) % n
        
        # Use itertools.islice for memory-efficient chunking
        it = iter(lst)
        chunks = []
        
        for i in range(n):
            # Add one extra item to the first 'remainder' chunks
            current_chunk_size = chunk_size + (1 if i < remainder else 0)
            chunk = list(itertools.islice(it, current_chunk_size))
            if chunk:  # Only add non-empty chunks
                chunks.append(chunk)
        
        return chunks
    
    # Create chunks
    chunks = chunk_list(all_ap_numbers, num_chunks)
    
    if output_format == 'json':
        if num_chunks == 1:
            # Single chunk - save as simple JSON list
            with open(output_file, 'w') as f:
                json.dump(all_ap_numbers, f, indent=2)
        else:
            # Multiple chunks - save as JSON object with numbered keys
            chunked_data = {}
            for i, chunk in enumerate(chunks, 1):
                chunked_data[str(i)] = chunk
            
            with open(output_file, 'w') as f:
                json.dump(chunked_data, f, indent=2)
    else:  # text format
        if num_chunks == 1:
            # Single chunk - save to single file
            with open(output_file, 'w') as f:
                for ap_number in all_ap_numbers:
                    f.write(f"{ap_number}\n")
        else:
            # Multiple chunks - save to separate files
            base_name = os.path.splitext(output_file)[0]
            extension = os.path.splitext(output_file)[1] or '.txt'
            
            for i, chunk in enumerate(chunks, 1):
                chunk_filename = f"{base_name}_{i}{extension}"
                with open(chunk_filename, 'w') as f:
                    for ap_number in chunk:
                        f.write(f"{ap_number}\n")
    
    # Print comprehensive summary
    total_ap_numbers = len(all_ap_numbers) + len(all_omitted_numbers)
    print("\n" + "="*60)
    print("PROCESSING SUMMARY")
    print("="*60)
    print(f"Total files processed: {files_processed}")
    print(f"Total AP numbers across files: {total_ap_numbers}")
    print(f"Total AP numbers collected: {len(all_ap_numbers)}")
    print(f"Total AP numbers omitted: {len(all_omitted_numbers)}")
    print(f"Output format: {output_format}")
    print(f"Number of chunks: {num_chunks}")
    
    if num_chunks == 1:
        print(f"Output file: {output_file}")
    else:
        if output_format == 'json':
            print(f"Output file: {output_file} (JSON object with {num_chunks} numbered keys)")
        else:
            base_name = os.path.splitext(output_file)[0]
            extension = os.path.splitext(output_file)[1] or '.txt'
            print(f"Output files: {base_name}_1{extension} through {base_name}_{num_chunks}{extension}")
            
            # Show chunk sizes
            for i, chunk in enumerate(chunks, 1):
                print(f"  Chunk {i}: {len(chunk)} AP numbers")
    
    if all_omitted_numbers:
        print(f"\nOmitted AP numbers ({len(all_omitted_numbers)}):")
        print("-" * 30)
        for omitted_number in all_omitted_numbers:
            print(omitted_number)
    else:
        print("\nNo AP numbers were omitted.")

if __name__ == "__main__":
    main()
