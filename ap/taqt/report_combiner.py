from bs4 import BeautifulSoup
import glob

# NOTE: Change these to the approproate format
# They are exam score report fillers right now
# REPORT_HEADER = "TAQT Report for View Scores QC"
REPORT_TYPE = 'past'
if REPORT_TYPE == 'past':
    REPORT_HEADER = "TAQT Report for Past Score Sends: Scores Sent to Institution QC"
    REPORT_SUBHEADER = "Data source file: APACIF20250628909.xml"
    REPORT_DATE = "Date of Report: 07/01/2025"
    REPORT_COUNT = "Number of Student/DI Records Qc'ed: 508"
    REPORT_SUCCESS_COUNT = "Number of Student/DI Records Passed: {success_count}"
    REPORT_ERROR_COUNT = "Number of Student/DI Records Errored: {error_count}"
    REPORT_UNIQUE_ERROR_ID_COUNT = "Unique error IDs: {error_count}"
    REPORT_ERROR_HEADER = "Registrations failed QC:"
    REPORT_SUCCESS_HEADER = "Registrations passed QC:"
elif REPORT_TYPE == 'exam':
    REPORT_HEADER = "TAQT Report for View Scores QC"
    REPORT_SUBHEADER = "Data source file: APACIF20250628909.xml"
    REPORT_DATE = "Date of Report: 06/29/2025"
    REPORT_COUNT = "Number of Student/DI Records Qc'ed: 508"
    REPORT_SUCCESS_COUNT = "Number of Student/DI Records Passed: {success_count}"
    REPORT_ERROR_COUNT = "Number of Student/DI Records Errored: {error_count}"
    REPORT_UNIQUE_ERROR_ID_COUNT = "Unique error IDs: {error_count}"
    REPORT_ERROR_HEADER = "Registrations failed QC:"
    REPORT_SUCCESS_HEADER = "Registrations passed QC:"
else:
    raise ValueError("Invalid REPORT_TYPE. Use 'past' or 'exam'.")



# NOTE: We check the error ids against the success ids to avoid duplicates in the error report.
# When I was first running TAQT and some network failure happened, or the code decided to not be able to detect it's target elements in the browser, there were some false positive errors.  Rerunning produced the real result successes for some of these, necessitating the need to check error ids against success ids, and prefer the latter.

def process_reports(filename_prefix, file_extension='html', report_output='combined_report.html'):
    # Track unique rows by status
    success_rows = set()
    success_ids = set()  # Track successful IDs so we can skip them in errors in case of duplicates
    error_rows = set()
    error_ids = set()  # Track error IDs because in exam reports there can be multiple errors 
                    # for the same ID, and we want to be sure our counts are sound
    
    report_files = []
    
    if not isinstance(filename_prefix, list) and not filename_prefix.endswith('*'):
        print("Warning: Filename prefix should end with '*' to match all files.")
        print("Attaching * to the end of the prefix.")
        filename_prefix += '*'
    
        # Glob for files with the given prefix and extension
        # This is built for html files, but can probably be adapted in some way
        report_files = glob.glob(f"{filename_prefix}.{file_extension}")
    
        if not report_files:
            print(f"No files found with prefix {filename_prefix} and extension {file_extension}.")
            return
    elif isinstance(filename_prefix, list):
        report_files = filename_prefix
    else:
        if isinstance(filename_prefix, list) and len(filename_prefix) == 0:
            print("Warning: Filename prefix list is empty.")
            return
    
    print(f"Processing {len(report_files)}")
    print(f"Files: {report_files}")
    print("Processing reports...")
    
    # First pass - collect all success records
    for report_file in report_files:
        with open(report_file, 'r') as f:
            soup = BeautifulSoup(f.read(), 'html.parser')
            
            tables = soup.find_all('table') # Grab the table by its tag (can handle multiple)
            for table in tables:
                rows = table.find_all('tr')[1:]  # Skip header row
                for row in rows:
                    # Get all cell values and clean them
                    cells = [cell.text.strip() for cell in row.find_all('td')]
                    if not cells:  # Skip null rows
                        continue
                    
                    row_data = tuple(cells)
                    
                    if cells[0] == 'Success':
                        success_rows.add(row_data)
                        success_ids.add(cells[1].strip())

    # Second pass - collect errors (skipping if ID exists in successes)
    for report_file in report_files:
        with open(report_file, 'r') as f:
            soup = BeautifulSoup(f.read(), 'html.parser')
            
            tables = soup.find_all('table')
            for table in tables:
                rows = table.find_all('tr')[1:]
                for row in rows:
                    cells = [cell.text.strip() for cell in row.find_all('td')]
                    if not cells:
                        continue
                        
                    row_data = tuple(cells)
                    
                    # Only add error if ID not in successes
                    if cells[0] == 'Error' and cells[1].strip() not in success_ids:
                        error_rows.add(row_data)
                        error_ids.add(cells[1].strip()) # collect unique error IDs for confirming counts against expected total

    # NOTE Change the globals at the top of the page to the appropriate values for the template variables
    template = """<!DOCTYPE html>
<html>
<body>
    <h1>{report_header}</h1>
    <br/>
    
    <h3>{report_subheader}</h3>
    <br />
    {report_date}<br />
    
    {report_count}<br />
    
    {report_success_count}<br/>
    
    {report_error_count}<br/>
    
    Number of Duplicate Records: 0<br>
    
    <br/>
    
    {report_error_header}<br />
    
    <table border="1">
        <tr>
            <th>Status</th>
            <th>AP Reg ID</th>
            <th>DI Code</th>
            <th>Sent Date</th>
            <th>Error Message</th>
        </tr>
        {error_rows}
    </table>
    
    <br/>
    
    {report_success_header}<br />
    
    <table border="1">
        <tr>
            <th>Status</th>
            <th>AP Reg ID</th>
            <th>DI Code</th>
            <th>Sent Date</th>
        </tr>
        {success_rows}
    </table>
</body>
</html>"""

    # Convert rows to HTML (assisted by Claude 3.5 Sonnet)
    error_html = '\n'.join([f"""        <tr>
            <td>{row[0]}</td>
            <td>&nbsp;{row[1]}&nbsp;</td>
            <td>{row[2]}</td>
            <td>{row[3]}</td>
            <td>{row[4] if len(row) > 4 else ''}</td>
        </tr>""" for row in sorted(error_rows)])

    success_html = '\n'.join([f"""        <tr>
            <td>{row[0]}</td>
            <td>&nbsp;{row[1]}&nbsp;</td>
            <td>{row[2]}</td>
            <td>{row[3]}</td>
        </tr>""" for row in sorted(success_rows)])

    combined_report = template.format(
        report_header=REPORT_HEADER,
        report_subheader=REPORT_SUBHEADER,
        report_date=REPORT_DATE,
        report_count=REPORT_COUNT,
        report_success_count=REPORT_SUCCESS_COUNT.format(success_count=len(success_rows)),
        report_error_count=REPORT_ERROR_COUNT.format(error_count=len(error_ids)),
        unique_error_id_count=REPORT_UNIQUE_ERROR_ID_COUNT.format(error_count=len(error_ids)),
        report_error_header=REPORT_ERROR_HEADER,
        report_success_header=REPORT_SUCCESS_HEADER,
        # success_count=len(success_rows),
        # error_count=len(error_rows),
        error_rows=error_html,
        success_rows=success_html
    )

    with open(report_output, 'w') as f:
        f.write(combined_report)

    print("Processing complete!")
    print(f"Total unique successful records: {len(success_rows)}")
    print(f"Total unique error records: {len(error_rows)}")
    print(f"Total unique error IDs: {len(error_ids)}")

# if __name__ == "__main__":
#     process_reports("exam_score_report", "html")