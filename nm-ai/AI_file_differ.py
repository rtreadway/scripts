"""
AI File Differ Script

This script processes AI data queries and generates comprehensive reports including:
1. Excel file diffing for merges and deletions (original functionality)
2. Additional analysis queries for current deletions, new records, and J-to-S transitions
3. Comprehensive markdown reporting

The script connects to a Redshift/PostgreSQL database, runs multiple SQL queries,
and produces both Excel output (for historical tracking) and markdown reports
(for comprehensive analysis).

Key Features:
- Abstracts Excel diffing into reusable functions
- Processes additional queries for enhanced reporting
- Generates markdown reports with executive summaries and detailed analysis
- Maintains backward compatibility with existing Excel workflows

Usage:
    python AI_file_differ.py <env> --infile <path_to_prior_xlsx> [options]
"""
import argparse
import os
import datetime
import logging

import boto3
import pandas as pd
from openpyxl import load_workbook

from src.db_ops import get_cornerstone_connection, iterate_queries, run_query
from src.excel_diff import process_excel_diff
from src.reporting import export_stats_for_email, generate_markdown_report
from src.utils import build_workdir, ensure_dir, extract_and_increment_month

logger = logging.getLogger(__name__)

def main():
    p = argparse.ArgumentParser(description="Run monthly Redshift queries and diff against prior XLSX")
    default_outdir = os.path.join(os.path.dirname(__file__), "_tmp")
    default_template = os.path.join(os.path.dirname(__file__), "templates/AI File Posting Template.msg")
    base_group = p.add_argument_group("Base")
    base_group.add_argument("env", default="qa", help="Environment name for DB connection (e.g. prod, staging)")
    base_group.add_argument("--admin-year", default=2025, help="Admin year for schema names (e.g. 2025)")
    base_group.add_argument("--month", help="Override the auto-determined YYYY-MM string for this run (e.g. 2025-06)")
    base_group.add_argument("--infile", required=True, help="Path to Merges and Deletions xlsx file from prior month to diff against")

    override_group = p.add_argument_group("Prep overrides")
    override_group.add_argument("--previous-year", type=int, help="Override previous_ai_customer using max filename from a specific historic year")
    override_group.add_argument("--previous-run-id", help="Override previous_ai_customer with an explicit run_id value")
    override_group.add_argument("--current-daily-year", type=int, help="Override current_ai_daily using max run_id from a specific historic year")
    override_group.add_argument("--current-daily-run-id", help="Override current_ai_daily with an explicit run_id value")

    output_group = p.add_argument_group("Output")
    output_group.add_argument("--outdir", default=default_outdir, help="Where to write new Merges and Deletions xlsx file and other outputs (report, diff xlsx, stats json, email, etc.)")
    output_group.add_argument("--workdir", default=".", help="Subdirectory under outdir for intermediate files (default: outdir)")
    output_group.add_argument("--detail-report", "-d", action="store_true", help="Generate detailed Excel diff report with separate sheets for added/removed/changed rows")
    output_group.add_argument("--no-report", action="store_true", help="Skip markdown report generation")

    email_group = p.add_argument_group("Email")
    email_group.add_argument("--email-template", default=default_template, help="Path to .msg email template to populate with collected stats")
    email_group.add_argument("--no-email", action="store_true", help="Skip email generation")

    logging_group = p.add_argument_group("Logging")
    logging_group.add_argument("--profile", "-p", default="default", help="AWS profile name")
    logging_group.add_argument("--verbose", "-v", action="store_true", help="Print detailed console output during processing")
    logging_group.add_argument("--log-file", help="Write logs to this file in addition to stdout")
    logging_group.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Set logging level (default: INFO)")
    args =  p.parse_args()

    log_level = getattr(logging, args.log_level.upper(), logging.INFO)
    logging.getLogger().setLevel(log_level)

    if args.log_file:
        log_dir = os.path.dirname(args.log_file)
        if log_dir:
            ensure_dir(log_dir)
        file_handler = logging.FileHandler(args.log_file, encoding="utf-8")
        file_handler.setLevel(log_level)
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
        )
        file_handler.setFormatter(formatter)
        logging.getLogger().addHandler(file_handler)

    base_dir = os.path.dirname(__file__)
    config_path = os.path.join(base_dir, "config", "excel_diff.json")
    report_template_path = os.path.join(base_dir, "templates", "ai_report.md.j2")
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Missing config file: {config_path}")
    if not args.no_report and not os.path.exists(report_template_path):
        raise FileNotFoundError(f"Missing report template: {report_template_path}")
    if not args.no_email and args.email_template and not os.path.exists(args.email_template):
        raise FileNotFoundError(f"Missing email template: {args.email_template}")
    
    boto3.setup_default_session(profile_name=args.profile)
    conn = get_cornerstone_connection(args.env)
    ensure_dir(args.outdir)
    workdir = build_workdir(args.outdir, args.workdir)
    
    if args.verbose:
        logger.info(f"Using {conn.get_engine_type()} database engine")
    
    email_stats = {
        'current_year': '',
        'previous_mo': '',
        'current_mo': '',
        'current_ai_daily': '',
        'previous_ai_customer': '',
        
        'ai_current_deletions_count': '',
        'ai_current_new_count': '',
        'ai_current_changes_count': '',
        'ai_total_current_records': '',
        
        'ai_char_diffs_net': '',
        'ai_char_diffs_added': '',
        'ai_char_diffs_removed': '',
        'ai_char_diffs_row_changes': '',
        'prev_total_char_diffs': '',
        'total_ai_char_diffs': '',
        
        'ai_domestic_net': '',
        'ai_domestic_added': '',
        'ai_domestic_removed': '',
        'ai_domestic_row_changes': '',
        'prev_total_domestic_diffs': '',
        'total_ai_domestic_trunc': '',
        
        'ai_intl_net': '',
        'ai_intl_removed': '',
        'ai_intl_added': '',
        'ai_intl_row_changes': '',
        'prev_total_intl_diffs': '',
        'total_ai_intl_trunc': '',
        
        's_to_j_switches': '',
        'j_to_s_switches': '',
        
        'historic_schema_yearly': '',
        'current_schema_yearly': '',
        'historic_schema_all': '',
        'current_schema_all': '',
    }
    
    if args.env != 'prod':
        email_stats['current_schema_yearly'] = f"team_rp__nm_current_{args.admin_year}_{args.env}"
        email_stats['historic_schema_yearly'] = f"team_rp__nm_historic_{args.admin_year}_{args.env}"
        email_stats['current_schema_all'] = f"team_rp__nm_current_all_{args.env}"
        email_stats['historic_schema_all'] = f"team_rp__nm_historic_all_{args.env}"
    else:
        email_stats['current_schema_yearly'] = f"team_rp__nm_current_{args.admin_year}"
        email_stats['historic_schema_yearly'] = f"team_rp__nm_historic_{args.admin_year}"
        email_stats['current_schema_all'] = "team_rp__nm_current_all"
        email_stats['historic_schema_all'] = "team_rp__nm_historic_all"
    
    # Prep existing xlsx file data and determine target month for diffing
    if args.month:
        target_month = args.month
        email_stats['current_mo'] = target_month
        if args.verbose:
            logger.info(f"Using manually specified month: {target_month}")
    else:
        previous_month, target_month = extract_and_increment_month(args.infile)
        email_stats['current_mo'] = target_month
        email_stats['previous_mo'] = previous_month
        if args.verbose:
            logger.info(f"Auto-incremented month from input filename: {target_month}")
    email_stats['current_year'] = str(datetime.datetime.now().year)
    
    if os.path.exists(args.infile):
        old_sheets = pd.read_excel(args.infile, sheet_name=None, dtype=str)
        # Clean up old sheets: strip whitespace from column names and string columns
        for df in old_sheets.values():
            df.columns = df.columns.str.strip()
            for c in df.select_dtypes(include="object"):
                df[c] = df[c].str.strip()
        if args.verbose:
            logger.info(f"Loaded existing workbook with {len(old_sheets)} sheets")
    else:
        raise FileNotFoundError(f"Input file {args.infile} does not exist.")

    # Get prep data for queries
    if args.verbose:
        logger.info("Getting necessary data from prep queries...")

    historic_schema_for_year = email_stats['historic_schema_yearly']
    daily_schema_for_year = email_stats['historic_schema_yearly']
    if args.previous_year:
        if args.env != 'prod':
            historic_schema_for_year = f"team_rp__nm_historic_{args.previous_year}_{args.env}"
        else:
            historic_schema_for_year = f"team_rp__nm_historic_{args.previous_year}"
    if args.current_daily_year:
        if args.env != 'prod':
            daily_schema_for_year = f"team_rp__nm_historic_{args.current_daily_year}_{args.env}"
        else:
            daily_schema_for_year = f"team_rp__nm_historic_{args.current_daily_year}"

    PREP_QUERIES = {
        "previous_ai_customer": f"SELECT max(filename) as run_id FROM {historic_schema_for_year}.ai_customer",
        "current_ai_daily": f"SELECT max(run_id) as run_id FROM {daily_schema_for_year}.ai_daily",
    }

    def _get_required_run_id(query_key, query_sql):
        """Run a prep query that is expected to return a single run_id value."""
        result_df = run_query(conn, query_sql)
        if result_df.empty or 'run_id' not in result_df.columns:
            raise ValueError(f"Prep query {query_key} returned no run_id")
        run_id = result_df.iloc[0]['run_id']
        if run_id is None or pd.isna(run_id) or str(run_id).strip() == "":
            raise ValueError(f"Prep query {query_key} returned empty run_id")
        return str(run_id).strip()

    for k, v in PREP_QUERIES.items():
        if k == "previous_ai_customer" and args.previous_run_id:
            PREP_QUERIES[k] = str(args.previous_run_id).strip()
            continue
        if k == "current_ai_daily" and args.current_daily_run_id:
            PREP_QUERIES[k] = str(args.current_daily_run_id).strip()
            continue
        v = v.format(**email_stats)
        if args.verbose:
            logger.info(f"Running query for {k}: {v}")
        PREP_QUERIES[k] = _get_required_run_id(k, v)
    email_stats['current_ai_daily'] = PREP_QUERIES['current_ai_daily']
    email_stats['previous_ai_customer'] = PREP_QUERIES['previous_ai_customer']
    
    if args.verbose:
        logger.info("Prepared Queries:", PREP_QUERIES)
    
    # Create temp tables
    if args.verbose:
        logger.info("Creating temporary tables...")
    iterate_queries(conn, args, "ai_diff_temp_tables", return_result=False, parameter_overrideD=email_stats)
    if args.verbose:
        logger.info("Temporary tables created.")
    
    if args.verbose:
        logger.info("Creating secondary temporary tables...")
    iterate_queries(conn, args, "ai_secondary_temp_tables", return_result=False, parameter_overrideD=email_stats)
    if args.verbose:
        logger.info("Secondary temporary tables created.")

    # Process additional queries for stats
    MAIN_QUERIES = [
        'ai_total_current_records',
        'ai_current_changes_count',
        'ai_current_deletions_count',
        'ai_current_new_count', 
        'ai_current_deletions',
        'ai_j_to_s_detail',
        'ai_s_to_j_detail'
    ]
    additional_results = iterate_queries(conn, args, "ai_diff_queries", return_result=True, query_filterL=MAIN_QUERIES)
    
    # Process Excel diffing and populate Deletions sheet
    wb = load_workbook(args.infile)
    diff_report, detail_dfs = process_excel_diff(conn, args, target_month, old_sheets, wb, additional_results, email_stats)
    
    # Export stats first so markdown can include them
    stats_json_path = os.path.join(workdir, f"ai_stats_{target_month.replace(' ', '_')}.json")
    additional_query_stats = export_stats_for_email(additional_results, base_stats=email_stats, output_path=stats_json_path)
    email_stats.update(additional_query_stats)

    # Generate markdown report (includes stats snapshot)
    report_path = None
    if not args.no_report:
        report_path = generate_markdown_report(
            target_month,
            diff_report,
            additional_results,
            args,
            email_statsD=email_stats,
        )
    
    if args.verbose:
        logger.info("=== PRINTING EMAIL STATS ===")
        from pprint import pp
        pp(email_stats)
    logger.info("============================")

    # email generation if enabled
    if args.email_template and not args.no_email:
        logger.info("GENERATING STATS EMAIL")
        try:
            from src.email_generator import generate_ai_email_from_stats
            final_email_path = generate_ai_email_from_stats(args.email_template, email_stats, args.outdir)
            logger.info(f"Email generated at: {final_email_path}")
        except Exception as e:
            logger.error(f"Failed to generate email: {e}")

    # Final summary to console
    logger.info("=== DIFF SUMMARY ===")
    if diff_report:
        logger.info("\n" + pd.DataFrame(diff_report).to_string(index=False))
    
    if args.verbose:
        logger.info("=== ADDITIONAL STATS ===")
        for query_name, result_df in additional_results.items():
            if 'count' in query_name.lower():
                count_val = result_df.iloc[0, 0] if not result_df.empty else 0
                logger.info(f"{query_name}: {count_val:,}")
            else:
                logger.info(f"{query_name}: {len(result_df):,} rows")
    else:
        logger.info("Not printing additional stats. Use --verbose for more details or see the report.")
    
    if report_path:
        logger.info(f"Comprehensive report saved to: {report_path}")
    

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    logger.info("Starting AI File Differ script...")
    main()
    logger.info("AI File Differ script completed.")
