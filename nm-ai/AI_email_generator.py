# AI Email Generator - Generate AI statistics emails from templates
import html
import re
import os
import subprocess
import sys
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import extract_msg

def safely_load_msg(msg_path):
    try:
        return extract_msg.Message(msg_path)
    except Exception as e:
        raise ValueError(f"Failed to read .msg file: {e}")

def msg_extract_body_html_from_msg(msg_path):
    m = safely_load_msg(msg_path)
    html_body = m.htmlBody
    if html_body:
        # Handle case where htmlBody is bytes
        if isinstance(html_body, bytes):
            html_body = html_body.decode('utf-8', errors='ignore')
    else:
        # basic escape for plain text → HTML
        body = m.body or ""
        if isinstance(body, bytes):
            body = body.decode('utf-8', errors='ignore')
        body = html.escape(body)
        html_body = f"<html><body><pre style='font-family:Segoe UI, sans-serif'>{body}</pre></body></html>"
    return html_body

def msg_to_eml_template(msg_path: str, eml_template_path: str) -> str:
    m = safely_load_msg(msg_path)

    from_addr = m.sender or ""
    to_addrs  = [a.strip() for a in (m.to or "").replace(";", ",").split(",") if a.strip()]
    cc_addrs  = [a.strip() for a in (m.cc or "").replace(";", ",").split(",") if a.strip()]
    bcc_addrs = [a.strip() for a in (m.bcc or "").replace(";", ",").split(",") if a.strip()]
    subject   = m.subject or ""

    # Prefer HTML if present; fall back to plain text
    html_body = m.htmlBody
    if html_body:
        # Handle case where htmlBody is bytes
        if isinstance(html_body, bytes):
            html_body = html_body.decode('utf-8', errors='ignore')
    else:
        # basic escape for plain text → HTML
        body = m.body or ""
        if isinstance(body, bytes):
            body = body.decode('utf-8', errors='ignore')
        body = html.escape(body)
        html_body = f"<html><body><pre style='font-family:Segoe UI, sans-serif'>{body}</pre></body></html>"

    # Build a portable .eml (MIME) template
    eml = MIMEMultipart()
    
    # Use the original sender address, or fallback to default
    eml["From"] = from_addr if from_addr else "me@example.com"
    if to_addrs:
        eml["To"] = ", ".join(to_addrs)
    if cc_addrs:
        eml["Cc"] = ", ".join(cc_addrs)
    if bcc_addrs:
        eml["Bcc"] = ", ".join(bcc_addrs)
    eml["Subject"] = subject

    # Keep placeholders (e.g., {{total_users}}) as-is for later replacement
    eml.attach(MIMEText(str(html_body), "html"))

    with open(eml_template_path, "wb") as f:
        f.write(eml.as_bytes())

    return eml_template_path

def collect_ai_stats(env, prev_file_path):
    """
    Collect AI statistics by running AI_file_differ.py and reading the generated JSON stats.
    Returns a dictionary of stats that can be used to replace placeholders.
    """
    try:
        # Run AI_file_differ.py to generate stats
        cmd = [
            "python", "AI_file_differ.py", env,
            "--infile", prev_file_path,
            "--verbose"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=os.path.dirname(__file__))
        
        if result.returncode != 0:
            print(f"AI_file_differ.py failed: {result.stderr}")
            return get_default_stats()
        
        # Look for the generated JSON stats file
        target_month = extract_month_from_filename(prev_file_path)
        stats_json_path = f"ai_stats_{target_month.replace(' ', '_')}.json"
        
        if os.path.exists(stats_json_path):
            import json
            with open(stats_json_path, 'r') as f:
                stats = json.load(f)
        else:
            print(f"Stats JSON file not found: {stats_json_path}")
            stats = {}
        
        # Add computed values
        current_date = datetime.now()
        stats["current_ai_daily"] = current_date.strftime("%Y-%m-%d")
        
        # Calculate previous month period from filename or date
        prev_filename = os.path.basename(prev_file_path)
        stats["previous_ai_customer"] = prev_filename.replace(".xlsx", "").replace("_", " ")
        
        # Fill in missing placeholders with default values
        default_stats = get_default_stats()
        for key, default_value in default_stats.items():
            if key not in stats:
                stats[key] = default_value
        
        return stats
        
    except Exception as e:
        print(f"Error collecting AI stats: {e}")
        return get_default_stats()

def extract_month_from_filename(filename):
    """Extract target month from filename for consistent naming."""
    # This is a simplified version - you might want to enhance based on actual filename patterns
    # basename = os.path.basename(filename)
    # For now, just use current date
    return datetime.now().strftime("%Y-%m")

def get_default_stats():
    """Return default placeholder statistics"""
    return {
        "current_ai_daily": datetime.now().strftime("%Y-%m-%d"),
        "previous_ai_customer": "Previous Month",
        "total_deletions": "0",
        "total_new": "0",
        "total_updated": "0",
        "total_current_records": "0",
        "total_ai_char_diffs": "0",
        "total_ai_domestic_trunc": "0",
        "total_ai_intl_trunc": "0",
        "ai_domestic_added": "0",
        "ai_domestic_removed": "0",
        "ai_domestic_row_changes": "0",
        "ai_intl_added": "0",
        "ai_intl_removed": "0",
        "ai_intl_row_changes": "0",
        "s_to_j_switches": "0",
        "j_to_s_switches": "0"
    }

# Placeholder functions for calculating specific statistics
# These would connect to your database and run specific queries
def calculate_updated_count(env):
    """Calculate number of updated records"""
    # TODO: Implement actual database query
    return "0"

def calculate_current_records(env):
    """Calculate total current records"""
    # TODO: Implement actual database query
    return "0"

def calculate_char_diffs(env):
    """Calculate character differences"""
    # TODO: Implement actual database query
    return "0"

def calculate_domestic_trunc(env):
    """Calculate domestic truncations"""
    # TODO: Implement actual database query
    return "0"

def calculate_intl_trunc(env):
    """Calculate international truncations"""
    # TODO: Implement actual database query
    return "0"

def calculate_domestic_added(env):
    """Calculate domestic records added"""
    # TODO: Implement actual database query
    return "0"

def calculate_domestic_removed(env):
    """Calculate domestic records removed"""
    # TODO: Implement actual database query
    return "0"

def calculate_domestic_changes(env):
    """Calculate domestic row changes"""
    # TODO: Implement actual database query
    return "0"

def calculate_intl_added(env):
    """Calculate international records added"""
    # TODO: Implement actual database query
    return "0"

def calculate_intl_removed(env):
    """Calculate international records removed"""
    # TODO: Implement actual database query
    return "0"

def calculate_intl_changes(env):
    """Calculate international row changes"""
    # TODO: Implement actual database query
    return "0"

def calculate_s_to_j_switches(env):
    """Calculate S to J switches"""
    # TODO: Implement actual database query or parse from AI_file_differ output
    return "0"

def calculate_j_to_s_switches(env):
    """Calculate J to S switches"""
    # TODO: Implement actual database query or parse from AI_file_differ output
    return "0"

def replace_placeholders_in_html(html_content, stats_dict):
    """
    Replace {{placeholder}} patterns in HTML content with values from stats_dict.
    Handles complex HTML patterns like {{<span class=SpellE>placeholder</span>}}
    """
    # Define regex pattern to match both simple and complex placeholders
    pattern = r'\{\{(?:<[^>]*>)*([^}]+?)(?:</[^>]*>)*\}\}'
    
    def replacement_func(match):
        # Extract the placeholder name from the match
        full_match = match.group(0)
        placeholder_content = match.group(1)
        # Clean up the placeholder name (remove HTML tags and extra spaces)
        placeholder_name = re.sub(r'<[^>]*>', '', placeholder_content).strip()
        # Simple placeholder replacement, with special formatting for "net" placeholders
        value = stats_dict.get(placeholder_name, full_match)
        name_lower = placeholder_name.lower()
        if 'net' in name_lower:
            s = str(value).strip()
            try:
                n = int(s.replace(',', ''))
                if n > 0:
                    return f"+{n}"
                else:
                    return str(n)
            except Exception:
                # If not an integer, fall back to raw string
                return str(value)
        return str(value)

    return re.sub(pattern, replacement_func, html_content)

def generate_ai_email_from_stats(msg_template_path: str, stats_dict: dict, output_eml_path: str) -> str:
    """Generate an email (.eml) from a .msg template using provided stats dict without rerunning pipelines.

    If output_eml_path is a directory (or has no extension), the file name will be derived from the populated Subject.
    """
    # Normalize stats to strings to prevent type issues in template substitution
    stats_dict = {k: ("" if v is None else str(v)) for k, v in stats_dict.items()}
    # Extract HTML content from the template
    template_html = msg_extract_body_html_from_msg(msg_template_path)
    # Replace placeholders
    populated_html = replace_placeholders_in_html(template_html, stats_dict)
    # Build EML using headers from .msg when available
    template_msg = safely_load_msg(msg_template_path)
    eml = MIMEMultipart()
    eml["From"] = template_msg.sender or "me@example.com"
    if template_msg.to:
        eml["To"] = template_msg.to
    if template_msg.cc:
        eml["Cc"] = template_msg.cc
    if template_msg.bcc:
        eml["Bcc"] = template_msg.bcc
    # Subject with placeholders replaced; default uses month/year placeholders if template has no subject
    subject_template = template_msg.subject or "AI File Posting: {{previous_mo}}-{{current_mo}} {{current_year}}"
    # Use same replacer for subject text
    populated_subject = replace_placeholders_in_html(subject_template, stats_dict)
    # Remove forbidden filename chars and specifically colons from the subject for filename friendliness
    safe_subject = re.sub(r'[\\/*?"<>|]', '', populated_subject).replace(':', '')
    eml["Subject"] = populated_subject
    # Attach populated HTML
    eml.attach(MIMEText(str(populated_html), "html"))
    # Determine output path: if output_eml_path is a directory or has no extension, build filename from subject
    out_path = output_eml_path
    root, ext = os.path.splitext(output_eml_path)
    if os.path.isdir(output_eml_path) or ext == '':
        out_dir = output_eml_path if os.path.isdir(output_eml_path) else os.path.dirname(msg_template_path)
        if not out_dir:
            out_dir = os.getcwd()
        out_filename = f"{safe_subject}.eml"
        out_path = os.path.join(out_dir, out_filename)
    # Write out
    with open(out_path, "wb") as f:
        f.write(eml.as_bytes())
    return out_path

def generate_ai_stats_email(msg_template_path, env, prev_file_path, output_eml_path):
    """
    Generate an AI statistics email by:
    1. Collecting current AI stats
    2. Loading the email template 
    3. Replacing placeholders with current values
    4. Generating the final .eml file
    """
    try:
        # Step 1: Collect current AI statistics
        print("Collecting AI statistics...")
        stats = collect_ai_stats(env, prev_file_path)
        print(f"Collected {len(stats)} statistics")
        
        # Step 2: Extract HTML content from the template
        print("Extracting template content...")
        template_html = msg_extract_body_html_from_msg(msg_template_path)
        
        # Step 3: Replace placeholders with actual values
        print("Replacing placeholders...")
        populated_html = replace_placeholders_in_html(template_html, stats)
        
        # Step 4: Create the email message with populated content
        print("Generating email...")
        template_msg = safely_load_msg(msg_template_path)
        
        eml = MIMEMultipart()
        eml["From"] = template_msg.sender or "rtreadway@collegeboard.org"
        eml["To"] = template_msg.to or "recipients@example.com"
        eml["Subject"] = template_msg.subject or f"AI Statistics Report - {stats['current_ai_daily']}"
        
        # Attach the populated HTML content
        eml.attach(MIMEText(populated_html, "html"))
        
        # Step 5: Save the final email
        with open(output_eml_path, "wb") as f:
            f.write(eml.as_bytes())
        
        print(f"AI statistics email generated: {output_eml_path}")
        return output_eml_path
        
    except Exception as e:
        print(f"Error generating AI stats email: {e}")
        raise

if __name__ == "__main__":
    # Example usage
    if len(sys.argv) >= 4:
        msg_template = sys.argv[1]
        environment = sys.argv[2] 
        prev_file = sys.argv[3]
        output_file = sys.argv[4] if len(sys.argv) > 4 else "ai_stats_email.eml"
        
        generate_ai_stats_email(msg_template, environment, prev_file, output_file)
    else:
        # Default test
        email = msg_extract_body_html_from_msg("AI File Posting Template.msg")
        
        with open("test.txt", "w", encoding='utf-8') as f:
            f.write(str(email))