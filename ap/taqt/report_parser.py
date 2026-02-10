import argparse
import re
import xml.etree.ElementTree as ET
import glob
import os
import hashlib
from collections import defaultdict, Counter
from itertools import combinations

from bs4 import BeautifulSoup
from ACIF_splitter import get_xml_ids, extract_records_by_ids

from report_combiner import process_reports

def open_html_file(filename):
    """
    Open an HTML file and return its content as a BeautifulSoup object.
    
    Args:
        filename (str): The name of the HTML file to open.
        
    Returns:
        BeautifulSoup: The parsed HTML content.
    """
    with open(filename, 'r') as f:
        soup = BeautifulSoup(f.read(), 'html.parser')
    return soup

def extract_table_data(soup, cell_filter_f=None, cell_Filter_keyword=None):
    """
    Extract data from tables in a BeautifulSoup object.
    
    Args:
        soup (BeautifulSoup): The parsed HTML content.
        
    Returns:
        list: A list of tuples containing the extracted data.
    """
    tables = soup.find_all('table')
    data = []
    
    for table in tables:
        rows = table.find_all('tr')[1:]  # Skip header row
        for row in rows:
            cells = [cell.text.strip() for cell in row.find_all('td')]
            if not cells:
                continue
            data.append(tuple(cells))
    
    if cell_filter and cell_Filter_keyword:
        data = [row for row in data if cell_filter(row, cell_Filter_keyword)]
    elif (cell_filter and not cell_Filter_keyword) or (not cell_filter and cell_Filter_keyword):
        raise ValueError("cell_Filter_keyword must be provided if cell_filter is used")
    
    return data

def parse_error_row_data(error_rows):
    from collections import Counter
    error_type_counter = Counter()
    errors_by_id = defaultdict(list)
    for row in error_rows:
        ap_reg_id = row[1].strip()
        error_msg = row[4]
        errors_by_id[ap_reg_id].append(error_msg)
    
    errors_by_di = defaultdict(list)
    for row in error_rows:
        di_code = row[2]
        error_msg = row[4]
        errors_by_di[di_code].append(error_msg)

    # Categorize errors by type
    def categorize_error(msg):
        if "No search results found" in msg:
            return "Not Found"
        elif "does not match" in msg:
            return "Name Mismatch"
        elif "not found on View Scores Page" in msg:
            return "Missing on View Scores Page"
        elif "Score not found in Gold Source" in msg:
            return "Missing in Gold Source"
        elif "Error - during validation" in msg:
            return "Validation Error"
        elif "Event CD" in msg:
            return "Event CD Error"
        else:
            return "Other"

    errors_by_type = defaultdict(list)
    for row in error_rows:
        error_type = categorize_error(row[4])
        error_type_counter[error_type] += 1
        errors_by_type[error_type].append(row)

    # Print summary
    print("\nError Type Distribution:")
    for etype, count in error_type_counter.most_common():
        print(f"{etype}: {count}")

    print("\nIDs with most errors:")
    for ap_reg_id, msgs in sorted(errors_by_id.items(), key=lambda x: len(x[1]), reverse=True)[:10]:
        print(f"{ap_reg_id}: {len(msgs)} errors")

    print("\nMost common error messages:")
    msg_counter = Counter(row[4] for row in error_rows)
    for msg, count in msg_counter.most_common(10):
        print(f"{count}x: {msg}")

    # Optional: Cross-tabulate by DI Code
    di_code_counter = Counter(row[2] for row in error_rows)
    print("\nDI Code Error Distribution:")
    for di, count in di_code_counter.most_common():
        print(f"DI Code {di}: {count} errors")
    
     # Errors per ID distribution
    from collections import Counter
    error_counts = Counter(len(msgs) for msgs in errors_by_id.values())
    print("\nErrors per AP Reg ID Distribution:")
    for num_errors, count in sorted(error_counts.items()):
        print(f"{count} IDs have {num_errors} errors")

    # Error type co-occurrence
    error_types_by_id = {
        ap_reg_id: set(categorize_error(msg) for msg in msgs)
        for ap_reg_id, msgs in errors_by_id.items()
    }
    co_occurrence = Counter()
    for types in error_types_by_id.values():
        for combo in combinations(sorted(types), 2):
            co_occurrence[combo] += 1
    print("\nTop Error Type Co-occurrences:")
    for (etype1, etype2), count in co_occurrence.most_common(10):
        print(f"{etype1} + {etype2}: {count} IDs")
    
    for di_code, msgs in errors_by_di.items():
        msg_counter = Counter(msgs)
        top_msg, top_count = msg_counter.most_common(1)[0]
        print(f"DI Code {di_code}: '{top_msg}' ({top_count} times)")
    
    unique_msgs = set(row[4] for row in error_rows)
    print(f"\nNumber of unique error messages: {len(unique_msgs)}")
    print("Unique error messages:")
    for msg in unique_msgs:
        print(f"- {msg}")
    
    error_counts = Counter(len(msgs) for msgs in errors_by_id.values())
    print("\nHistogram: Errors per AP Reg ID")
    for num_errors, count in sorted(error_counts.items()):
        print(f"{count} IDs have {num_errors} errors")
    
    import matplotlib.pyplot as plt

    # Suppose error_type_counter is a Counter from your parse_error_row_data
    # labels, values = zip(*error_type_counter.most_common())
    # plt.bar(labels, values)
    # plt.title("Error Type Distribution")
    # plt.xlabel("Error Type")
    # plt.ylabel("Count")
    # plt.xticks(rotation=45)
    # plt.tight_layout()
    # plt.show()
    # Prepare data for heatmap
    import numpy as np
    import seaborn as sns
    error_types = sorted(error_type_counter.keys())
    matrix = np.zeros((len(error_types), len(error_types)), dtype=int)
    type_idx = {etype: i for i, etype in enumerate(error_types)}
    for (etype1, etype2), count in co_occurrence.items():
        i, j = type_idx[etype1], type_idx[etype2]
        matrix[i, j] = count
        matrix[j, i] = count  # symmetric

    plt.figure(figsize=(8, 6))
    sns.heatmap(matrix, annot=True, fmt="d", xticklabels=error_types, yticklabels=error_types, cmap="Blues")
    plt.title("Error Type Co-occurrence Heatmap")
    plt.xlabel("Error Type")
    plt.ylabel("Error Type")
    plt.tight_layout()
    plt.show()

def cell_filter(row, keyword):
    """
    Filter rows based on a keyword in the first cell.
    
    Args:
        row (tuple): A tuple representing a row of data.
        keyword (str): The keyword to filter by.
        
    Returns:
        bool: True if the row matches the keyword, False otherwise.
    """
    return row[0] == keyword

def extract_missing_records(xml_file, report_file, output_file):
    """
    Extract records that exist in the XML file but are not in the HTML report
    (neither as success nor error records).
    
    Args:
        xml_file (str): Path to the XML file containing all records.
        report_file (str): Path to the HTML report file.
        output_file (str): Path to save the extracted records.
    """
    # Get all IDs from the XML file
    all_xml_ids = get_xml_ids(xml_file)
    if not all_xml_ids:
        print("No IDs found in the XML file.")
        return
    
    print(f"Total unique IDs in XML file: {len(all_xml_ids)}")
    
    # Get success and error IDs from the HTML report
    soup = open_html_file(report_file)
    success_rows = extract_table_data(soup, cell_filter, 'Success')
    error_rows = extract_table_data(soup, cell_filter, 'Error')
    
    success_ids = {row[1].strip() for row in success_rows}
    error_ids = {row[1].strip() for row in error_rows}
    
    print(f"Success IDs in report: {len(success_ids)}")
    print(f"Error IDs in report: {len(error_ids)}")
    
    # Calculate missing IDs (IDs in XML but not in success or error lists)
    report_ids = success_ids.union(error_ids)
    missing_ids = all_xml_ids.difference(report_ids)
    
    print(f"Missing IDs (not in report): {len(missing_ids)}")
    print(f"First 10 missing IDs (sample): {list(missing_ids)[:10]}")
    
    # Extract records for missing IDs
    if missing_ids:
        extract_records_by_ids(xml_file, missing_ids, output_file)
        print(f"Extracted {len(missing_ids)} missing records to {output_file}")
    else:
        print("No missing records found.")
        
    return missing_ids

def extract_multi_di_records(xml_file, output_file):
    """
    Extract records for students who have scores sent to multiple DIs.
    
    Args:
        xml_file (str): Path to the XML file containing all records.
        output_file (str): Path to save the extracted records.
    
    Returns:
        set: Set of student IDs with multiple DIs.
    """
    # Get statistics including multi-DI students
    stats = collect_xml_stats(xml_file, verbose=False)
    
    if not stats or 'multi_di_students' not in stats:
        print("No multi-DI students found.")
        return set()
    
    multi_di_students = stats['multi_di_students']
    if not multi_di_students:
        print("No students with multiple DIs found.")
        return set()
    
    print(f"Found {len(multi_di_students)} students with multiple DIs.")
    
    # Extract records for these students
    extract_records_by_ids(xml_file, set(multi_di_students.keys()), output_file)
    print(f"Extracted records for {len(multi_di_students)} students to {output_file}")
    
    return set(multi_di_students.keys())

def analyze_duplicate_records(xml_file, detailed_output=False):
    """
    Analyze duplicate records in the XML file to determine if they have differences
    in their Exams, Awards, and DiInfo sections.
    
    Args:
        xml_file (str): Path to the XML file.
        detailed_output (bool): Whether to show detailed differences for each duplicate.
        
    Returns:
        dict: Dictionary containing analysis results.
    """
    # This is now just a wrapper around collect_xml_stats
    stats = collect_xml_stats(xml_file, verbose=False, detailed_duplicate_analysis=detailed_output)
    return stats.get('duplicate_analysis', {})

def collect_xml_stats(xml_file, verbose=True, detailed_duplicate_analysis=False):
    """
    Collect and display statistics from an XML file containing student records.
    
    Args:
        xml_file (str): Path to the XML file.
        
    Returns:
        dict: Dictionary containing the collected statistics.
    """   
    # Parse the XML file
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except Exception as e:
        print(f"Error parsing XML file: {e}")
        return None
    
    # Find all records
    records = root.findall('.//Record')
    total_records = len(records)
    
    # Initialize statistics containers
    student_ids = set()
    di_codes = Counter()
    di_code_combinations = Counter()
    exams = Counter()
    scores = defaultdict(Counter)
    gender_distribution = Counter()
    admin_years = Counter()
    id_counter = Counter()  # Track count of each ID
    duplicate_ids = set()
    ids_seen = set()
    student_di_mapping = defaultdict(set)  # Maps student ID to set of DI codes
    multi_di_students = {}  # Will store student IDs with multiple DI codes
    duplicate_analysis = {
        'identical_duplicates': 0,
        'different_exams': 0,
        'different_awards': 0,
        'different_diinfo': 0,
        'detailed_differences': defaultdict(dict)
    }
    
    # Process each record
    for record in records:
        # Extract student ID
        student_id_elem = record.find(".//StudentData[@value='APUID']")
        student_id = student_id_elem.text.strip() if student_id_elem is not None and student_id_elem.text else "Unknown"
        
        id_counter[student_id] += 1
        
        # Check for duplicates
        if id_counter[student_id] > 1 and student_id not in duplicate_ids:
            duplicate_ids.add(student_id)
        else:
            ids_seen.add(student_id)
        
        student_ids.add(student_id)
        
        # Extract gender
        gender_elem = record.find(".//StudentData[@value='gender']")
        gender = gender_elem.text.strip() if gender_elem is not None and gender_elem.text else "Unknown"
        gender_distribution[gender] += 1
        
        # Extract DI codes
        record_di_codes = []
        di_code_elems = record.findall(".//Di[@value='di_code']")
        for di_code_elem in di_code_elems:
            if di_code_elem.text:
                di_code = di_code_elem.text.strip()
                di_codes[di_code] += 1
                record_di_codes.append(di_code)
                if student_id != 'Unknown':
                    student_di_mapping[student_id].add(di_code)
        
        # Track DI code combinations (if multiple per record)
        if len(record_di_codes) > 1:
            di_code_combinations[tuple(sorted(record_di_codes))] += 1
        
        # Extract exam information
        exams_section = record.find('.//Exams')
        if exams_section is not None:
            for exam in exams_section.findall('.//Exam'):
                exam_name_elem = exam.find(".//Txt[@value='exam_name']")
                exam_score_elem = exam.find(".//Txt[@value='score']")
                admin_year_elem = exam.find(".//Txt[@value='admin_year']")
                
                exam_name = exam_name_elem.text.strip() if exam_name_elem is not None and exam_name_elem.text else "Unknown"
                exam_score = exam_score_elem.text.strip() if exam_score_elem is not None and exam_score_elem.text else "Unknown"
                admin_year = admin_year_elem.text.strip() if admin_year_elem is not None and admin_year_elem.text else "Unknown"
                
                exams[exam_name] += 1
                scores[exam_name][exam_score] += 1
                admin_years[admin_year] += 1
    
    # Get duplicate IDs with their counts (2 or more occurrences)
    duplicate_id_counts = {id: count for id, count in id_counter.items() if count > 1}
    
    # Find students with multiple DI codes
    for student_id, student_di_codes in student_di_mapping.items():
        if len(student_di_codes) > 1:
            multi_di_students[student_id] = student_di_codes
    
    if duplicate_ids:
        # Helper function to get XML section as a string for comparison
        def section_to_string(record, section_path):
            section = record.find(section_path)
            return ET.tostring(section, encoding='unicode') if section is not None else ""
        
        # Helper function to get hash of a section for quick comparison
        def get_section_hash(section_str):
            return hashlib.md5(section_str.encode()).hexdigest()
        
        # Group records by student ID
        records_by_id = defaultdict(list)
        for record in records:
            student_id_elem = record.find(".//StudentData[@value='APUID']")
            if student_id_elem is not None and student_id_elem.text:
                student_id = student_id_elem.text.strip()
                if student_id in duplicate_ids:
                    records_by_id[student_id].append(record)
        
        # Analyze each set of duplicate records
        for student_id, student_records in records_by_id.items():
            if len(student_records) <= 1:
                continue  # Skip if there's only one record (shouldn't happen for duplicate_ids)
                
            # Extract sections for comparison
            exams_sections = [section_to_string(rec, './/Exams') for rec in student_records]
            awards_sections = [section_to_string(rec, './/Awards') for rec in student_records]
            diinfo_sections = [section_to_string(rec, './/DiInfo') for rec in student_records]
            
            # Check for differences
            exams_different = len(set(get_section_hash(s) for s in exams_sections)) > 1
            awards_different = len(set(get_section_hash(s) for s in awards_sections)) > 1
            diinfo_different = len(set(get_section_hash(s) for s in diinfo_sections)) > 1
            
            # Record results
            if not exams_different and not awards_different and not diinfo_different:
                duplicate_analysis['identical_duplicates'] += 1
            else:
                if exams_different:
                    duplicate_analysis['different_exams'] += 1
                if awards_different:
                    duplicate_analysis['different_awards'] += 1
                if diinfo_different:
                    duplicate_analysis['different_diinfo'] += 1
            
            # Store detailed differences if requested
            if detailed_duplicate_analysis:
                differences = {}
                if exams_different:
                    differences['exams'] = []
                    for rec in student_records:
                        exams = rec.findall('.//Exam')
                        exam_details = []
                        for exam in exams:
                            exam_name = exam.find(".//Txt[@value='exam_name']")
                            exam_score = exam.find(".//Txt[@value='score']")
                            admin_year = exam.find(".//Txt[@value='admin_year']")
                            
                            exam_details.append({
                                'name': exam_name.text.strip() if exam_name is not None and exam_name.text else "Unknown",
                                'score': exam_score.text.strip() if exam_score is not None and exam_score.text else "Unknown",
                                'year': admin_year.text.strip() if admin_year is not None and admin_year.text else "Unknown"
                            })
                        differences['exams'].append(exam_details)
                
                if diinfo_different:
                    differences['diinfo'] = []
                    for rec in student_records:
                        record_di_codes = rec.findall(".//Di[@value='di_code']")
                        di_details = [di.text.strip() for di in record_di_codes if di.text]
                        differences['diinfo'].append(di_details)
                
                if awards_different:
                    differences['awards'] = []
                    for rec in student_records:
                        awards = rec.findall('.//Award')
                        award_details = []
                        for award in awards:
                            award_text = ET.tostring(award, encoding='unicode')
                            award_details.append(award_text)
                        differences['awards'].append(award_details)
                
                duplicate_analysis['detailed_differences'][student_id] = differences
    
    # Print summary statistics
    print(f"\nXML Statistics for {xml_file}")
    print("-" * 50)
    print(f"Total Records: {total_records}")
    print(f"Unique Student IDs: {len(student_ids)}")
    print(f"Duplicate IDs: {len(duplicate_ids)}")
    
    if duplicate_ids:
        total_duplicate_records = sum(count - 1 for count in duplicate_id_counts.values())
        print(f"Total duplicate records: {total_duplicate_records}")
        if verbose:
            print("Duplicate ID counts:")
            for dup_id, count in sorted(duplicate_id_counts.items(), key=lambda x: x[1], reverse=True):
                print(f"  {dup_id}: {count} occurrences")
        else:
            print(f"Sample Duplicate IDs: {list(duplicate_ids)[:5]}")
            print(f"  ... and {len(duplicate_ids) - 5} more duplicates")
    else:
        print("No duplicate IDs found.")
    
    print("\nTop 10 DI Codes:")
    for di_code, count in di_codes.most_common(10):
        print(f"  {di_code}: {count} records")
    
    if di_code_combinations:
        print("\nCommon DI Code Combinations:")
        for combo, count in di_code_combinations.most_common(5):
            print(f"  {' + '.join(combo)}: {count} records")
    
    print("\nMulti-DI Student Analysis:")
    print(f"Students with scores sent to multiple DIs: {len(multi_di_students)}")
    
    if multi_di_students:
        print("Top students by number of DI codes:")
        for student_id, di_codes in sorted(multi_di_students.items(), 
                                           key=lambda x: len(x[1]), 
                                           reverse=True)[:10]:
            print(f"  {student_id}: {len(di_codes)} DIs - {sorted(di_codes)}")
        
        # Distribution of number of DIs per student
        di_count_distribution = Counter(len(di_codes) for di_codes in multi_di_students.values())
        print("\nDistribution of DIs per student:")
        for count, num_students in sorted(di_count_distribution.items()):
            print(f"  {count} DIs: {num_students} students")
        
        # Most common DI combinations
        di_combinations = Counter(tuple(sorted(di_codes)) for di_codes in multi_di_students.values())
        print("\nMost common DI combinations:")
        for combo, count in di_combinations.most_common(5):
            print(f"  {' + '.join(combo)}: {count} students")
    
    print("\nTop 10 Exams:")
    for exam, count in exams.most_common(10):
        print(f"  {exam}: {count} exams")
    
    print("\nGender Distribution:")
    for gender, count in gender_distribution.items():
        print(f"  {gender}: {count} students ({count/total_records*100:.1f}%)")
    
    print("\nAdmin Years Distribution:")
    for year, count in sorted(admin_years.items()):
        print(f"  {year}: {count} exams")
    
    print("\nScore Distribution Summary:")
    for exam, score_counts in sorted(scores.items())[:5]:  # Show just top 5 exams
        print(f"  {exam}:")
        for score, count in sorted(score_counts.items()):
            print(f"    Score {score}: {count} students")
    
    print("\nDuplicate Record Analysis:")
    print(f"Total duplicate student IDs: {len(duplicate_ids)}")
    print(f"Identical duplicates: {duplicate_analysis['identical_duplicates']}")
    print(f"Duplicates with different exams: {duplicate_analysis['different_exams']}")
    print(f"Duplicates with different awards: {duplicate_analysis['different_awards']}")
    print(f"Duplicates with different DI info: {duplicate_analysis['different_diinfo']}")
    
    # Print detailed differences if requested
    if detailed_duplicate_analysis and duplicate_analysis['detailed_differences']:
        print("\nDetailed Differences:")
        for student_id, differences in duplicate_analysis['detailed_differences'].items():
            print(f"\nStudent ID: {student_id}")
            
            if 'exams' in differences:
                print("  Exam differences:")
                for i, exams in enumerate(differences['exams']):
                    print(f"    Record {i+1}:")
                    for exam in exams:
                        print(f"      {exam['name']} (Year: {exam['year']}, Score: {exam['score']})")
            
            if 'diinfo' in differences:
                print("  DI code differences:")
                for i, di_codes in enumerate(differences['diinfo']):
                    print(f"    Record {i+1}: {', '.join(di_codes)}")
            
            if 'awards' in differences:
                print("  Award differences found")
    
    # Return the statistics dictionary
    return {
        'total_records': total_records,
        'unique_student_ids': len(student_ids),
        'student_ids': student_ids,
        'duplicate_ids': duplicate_ids,
        'duplicate_id_counts': duplicate_id_counts,
        'di_codes': di_codes,
        'di_code_combinations': di_code_combinations,
        'exams': exams,
        'scores': scores,
        'gender_distribution': gender_distribution,
        'admin_years': admin_years,
        'multi_di_students': multi_di_students,
        'student_di_mapping': student_di_mapping,
        'duplicate_analysis': duplicate_analysis
    }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse HTML report and extract data.")
    parser.add_argument('--stats', '-s', action='store_true', help='Show statistics of the report.')
    parser.add_argument('--report_file', '-r', type=str, help='The HTML file to parse.')
    parser.add_argument('--cell_filter', type=str, help='The keyword to filter by in the first cell.')
    parser.add_argument('--acif_file', '-a', type=str, help='The full ACIF XML file to extract records from.')
    
    parser.add_argument('--xml_stats', '-x', action='store_true', help='Show statistics of the XML file.')
    parser.add_argument('--detailed_duplicates', '-dd', action='store_true', help='Show detailed differences between duplicate records.')
    
    parser.add_argument('--combine_reports', '-c', action='store_true', help='Combine multiple HTML reports into one.')
    parser.add_argument('--combine_report_files', '-cf', type=str, nargs='+', help='List of HTML report files to combine.')
    parser.add_argument('--combine_report_dir', '-cd', type=str, help='Directory containing HTML report files to combine.')
    parser.add_argument('--report_pattern', '-rp', type=str, default='*.html', help='File pattern for report files (default: *.html).')
    parser.add_argument('--combined_report', type=str, default='combined_report.html', help='The output HTML file to save combined records.')
    
    parser.add_argument('--extract_error_records', '-e', action='store_true', help='Extract records for error IDs.')
    parser.add_argument('--extracted_output_file', '-eo', type=str, default='extracted_error_ids_output.xml', help='The output XML file to save extracted records.')
    
    parser.add_argument('--extract_missing_records', '-m', action='store_true', help='Extract records that exist in XML but not in HTML report')
    parser.add_argument('--missing_output_file', '-mo', type=str, default='missing_records.xml', help='The output XML file to save missing records')
    
    parser.add_argument('--extract_multi_di', '-md', action='store_true', help='Extract records for students with multiple DI codes.')
    parser.add_argument('--multi_di_output', '-mdo', type=str, default='multi_di_records.xml', help='Output file for multi-DI student records.')
    
    parser.add_argument('--extract-by-apid', '-id', type=str, nargs='+', help='List of AP Registration IDs to extract from the ACIF file.')
    
    args = parser.parse_args()
    
    
    report_File = 'fails_from_5_20.html'
    
    unique_ids = get_xml_ids(args.acif_file) if args.acif_file else None
    if unique_ids is None:
        print("No unique IDs found in the XML file.")
        # exit(1)
    else:
        print("TOTAL UNIQUE IDs IN XML FILE: ", len(unique_ids))
    
    
    
    
    if args.stats:
        # Open the HTML file and parse it
        soup = open_html_file(args.report_file)
        # Extract success and error rows
        success_rows = extract_table_data(soup, cell_filter, 'Success')
        error_rows = extract_table_data(soup, cell_filter, 'Error')
        # Collect unique IDs for success and error rows
        success_ids = {row[1].strip() for row in success_rows}
        error_ids = {row[1].strip() for row in error_rows}
        # Collect unique error IDs for confirming counts against expected total
        unique_error_id_count = len(error_ids)
        # # Collect unique success IDs for confirming counts against expected total
        # unique_success_id_count = len(success_ids)
        # # Collect the total number of success and error rows
        # report_count = len(success_rows) + len(error_rows)
        # report_success_count = len(success_rows)
        report_error_count = len(error_rows)
        print("Statistics mode enabled.")
        # PRINT SECtION
        # print(f"Report Count: {report_count}")
        # print(f"Success Count: {report_success_count}")
        print(f"Error Count: {report_error_count}")
        # print(f"Unique Success IDs: {unique_success_id_count}")
        print(f"Unique Error IDs: {unique_error_id_count}")
        
        print(f"Unique Error IDs: {error_ids}")
        
        null_ids = set()
        
        for row in error_rows:
            # print(f"Error Row: {row}")
            if re.search(r'null\s+null', row[4]):
                null_ids.add(row[1].strip())
        
        print(f"Null IDs: {null_ids} of length {len(null_ids)}")
        
        parse_error_row_data(error_rows=error_rows)
    
    if args.xml_stats:
        if not args.acif_file:
            print("ACIF file not provided. Cannot analyze XML.")
            exit(1)
        collect_xml_stats(args.acif_file, detailed_duplicate_analysis=args.detailed_duplicates)
        
    # extract_records_by_ids("ACIF chunks/APACIF20250505114.xml", unique_ids, "APACIF_exam_error_ids.xml")
    if args.extract_error_records:
        # Open the HTML file and parse it
        soup = open_html_file(args.report_file)
        # Extract success and error rows
        success_rows = extract_table_data(soup, cell_filter, 'Success')
        error_rows = extract_table_data(soup, cell_filter, 'Error')
        # Collect unique IDs for success and error rows
        success_ids = {row[1].strip() for row in success_rows}
        error_ids = {row[1].strip() for row in error_rows}
        # Collect unique error IDs for confirming counts against expected total
        unique_error_id_count = len(error_ids)
        # # Collect unique success IDs for confirming counts against expected total
        # unique_success_id_count = len(success_ids)
        # # Collect the total number of success and error rows
        # report_count = len(success_rows) + len(error_rows)
        # report_success_count = len(success_rows)
        report_error_count = len(error_rows)
        # Extract records for error IDs
        print(f"Extracting records for error IDs: {error_ids}")
        if not args.acif_file:
            print("ACIF file not provided. Cannot extract records.")
            exit(1)
        
        extract_records_by_ids(args.acif_file, error_ids, args.extracted_output_file)
    
    elif args.extract_missing_records:
        if not args.acif_file:
            print("ACIF file not provided. Cannot extract missing records.")
            exit(1)
        if not args.report_file:
            print("Report file not provided. Cannot extract missing records.")
            exit(1)
            
        missing_ids = extract_missing_records(
            args.acif_file, 
            args.report_file, 
            args.missing_output_file
        )
    
    elif args.extract_multi_di:
        if not args.acif_file:
            print("ACIF file not provided. Cannot extract multi-DI student records.")
            exit(1)
        extract_multi_di_records(args.acif_file, args.multi_di_output)
    
    elif args.extract_by_apid:
        if not args.acif_file:
            print("ACIF file not provided. Cannot extract records by AP Registration IDs.")
            exit(1)
        extract_records_by_ids(args.acif_file, set(args.extract_by_apid), "extracted_by_apid.xml")
    
    # Combine multiple HTML reports into one
    elif args.combine_reports:
        report_files = []
        
        if args.combine_report_files:
            # Use manually specified files
            report_files = args.combine_report_files
            print(f"Combining manually specified reports: {report_files}")
        elif args.combine_report_dir:
            # Glob files from directory
            if not os.path.isdir(args.combine_report_dir):
                print(f"Error: Directory '{args.combine_report_dir}' does not exist.")
                exit(1)
            
            pattern = os.path.join(args.combine_report_dir, args.report_pattern)
            report_files = glob.glob(pattern)
            
            if not report_files:
                print(f"No files found matching pattern '{pattern}'")
                exit(1)
            
            print(f"Found {len(report_files)} files in directory '{args.combine_report_dir}':")
            for file in sorted(report_files):
                print(f"  - {file}")
        else:
            print("Error: Either --combine_report_files or --combine_report_dir must be specified with --combine_reports")
            exit(1)
        
        try:
            process_reports(report_files, report_output=args.combined_report)
            print(f"Combined report saved to: {args.combined_report}")
        except Exception as e:
            print(f"Error combining reports: {e}")
            exit(1)

    
    # Create dictionaries to store different types of errors
    # not_found_errors = {}  # For registration not found errors
    # name_mismatch_errors = {}  # For name mismatch errors
    # other_errors = {}  # For other types of errors
    
    # Process error rows and categorize them
    # for row in error_rows:
    #     student_id = row[1].strip()
    #     error_msg = row[4]
        
    #     # Add error to appropriate category
    #     if "No search results found" in error_msg:
    #         if student_id not in not_found_errors:
    #             not_found_errors[student_id] = []
    #         not_found_errors[student_id].append(error_msg)
        
    #     elif "Student Name" in error_msg and "does not match" in error_msg:
    #         if student_id not in name_mismatch_errors:
    #             name_mismatch_errors[student_id] = []
    #         name_mismatch_errors[student_id].append(error_msg)
        
    #     else:
    #         if student_id not in other_errors:
    #             other_errors[student_id] = []
    #         other_errors[student_id].append(error_msg)

    # # Print analysis
    # print("\nError Analysis:")
    # print("-" * 50)
    # print(f"\nRegistration Not Found Errors: {len(not_found_errors)} students")
    # for student_id, errors in not_found_errors.items():
    #     print(f"\nStudent ID: {student_id}")
    #     print(f"Number of errors: {len(errors)}")
    #     for error in errors:
    #         print(f"- {error}")

    # print(f"\nName Mismatch Errors: {len(name_mismatch_errors)} students")
    # for student_id, errors in name_mismatch_errors.items():
    #     print(f"\nStudent ID: {student_id}")
    #     print(f"Number of errors: {len(errors)}")
    #     for error in errors:
    #         print(f"- {error}")

    # # You can also look for overlapping issues
    # both_error_types = set(not_found_errors.keys()) & set(name_mismatch_errors.keys())
    # print(f"\nStudents with both registration and name issues: {len(both_error_types)}")
    # for student_id in both_error_types:
    #     print(f"\nStudent ID: {student_id}")

