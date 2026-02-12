import datetime
import json
import logging
import os

from jinja2 import Environment, FileSystemLoader, TemplateNotFound

logger = logging.getLogger(__name__)


def export_stats_for_email(additional_results, base_stats=None, output_path=None):
    """Export stats in JSON format for email template generation."""
    stats = {}

    if base_stats:
        stats.update(base_stats)

    for query_name, result_df in additional_results.items():
        name = query_name.lower()
        val = (result_df.iloc[0, 0] if not result_df.empty else 0)

        if 'deletions_count' in name:
            stats['ai_current_deletions_count'] = str(val)
        elif 'new_count' in name:
            stats['ai_current_new_count'] = str(val)
        elif 'changes_count' in name:
            stats['ai_current_changes_count'] = str(val)
        elif 'total_current_records' in name:
            stats['ai_total_current_records'] = str(val)
        elif not result_df.empty:
            if 'j_to_s_detail' in name:
                stats['j_to_s_switches'] = str(len(result_df)) or '0'
            elif 's_to_j_detail' in name:
                stats['s_to_j_switches'] = str(len(result_df)) or '0'

    if output_path:
        out_dir = os.path.dirname(output_path)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2)
        logger.info("Stats JSON written to %s", output_path)

    return stats


def generate_markdown_report(target_month, diff_report, additional_results, args, email_statsD=None):
    """Generate a comprehensive markdown report."""
    report_filename = f"AI_Report_{target_month.replace(' ', '_')}.md"
    report_path = os.path.join(args.outdir, report_filename)

    def _format_count(value, default='0'):
        try:
            if value is None:
                return default
            s = str(value)
            return f"{int(s):,}" if s.isdigit() else s
        except Exception:
            return default

    stats = email_statsD or {}
    stats_snapshot = None
    if stats:
        stats_snapshot = {
            "ai_total_current_records": _format_count(stats.get('ai_total_current_records')),
            "ai_current_new_count": _format_count(stats.get('ai_current_new_count')),
            "ai_current_deletions_count": _format_count(stats.get('ai_current_deletions_count')),
            "ai_current_changes_count": _format_count(stats.get('ai_current_changes_count')),
            "s_to_j_switches": _format_count(stats.get('s_to_j_switches')),
            "j_to_s_switches": _format_count(stats.get('j_to_s_switches')),
        }

    diff_totals = {"added": "0", "removed": "0", "changed": "0"}
    diff_rows = []
    if diff_report:
        total_added = sum(r['added'] for r in diff_report)
        total_removed = sum(r['removed'] for r in diff_report)
        total_changed = sum(r['row_changes'] for r in diff_report)
        diff_totals = {
            "added": f"{total_added:,}",
            "removed": f"{total_removed:,}",
            "changed": f"{total_changed:,}",
        }
        for report in diff_report:
            diff_rows.append({
                "sheet": report['sheet'],
                "added": f"{report['added']:,}",
                "removed": f"{report['removed']:,}",
                "changed": f"{report['row_changes']:,}",
            })

    def _row_value(row, *keys, default='N/A'):
        for key in keys:
            value = row.get(key)
            if value is not None:
                return str(value)
        return default

    deletions_section = None
    if 'ai_current_deletions' in additional_results and not additional_results['ai_current_deletions'].empty:
        deletions_df = additional_results['ai_current_deletions']
        too_many = len(deletions_df) > 100
        sample_df = deletions_df if not too_many else deletions_df.head(20)
        rows = []
        for _, row in sample_df.iterrows():
            rows.append({
                "ai_code": _row_value(row, 'ai_code', 'AI_CODE'),
                "ai_name": _row_value(row, 'ai'),
                "name": _row_value(row, 'name'),
                "address": _row_value(row, 'pn_address_line1'),
                "city": _row_value(row, 'pn_address_city'),
                "country": _row_value(row, 'pn_country'),
            })
        deletions_section = {
            "total": f"{len(deletions_df):,}",
            "too_many": too_many,
            "rows": rows,
        }

    jtos_section = None
    if 'ai_j_to_s_detail' in additional_results:
        jtos_df = additional_results['ai_j_to_s_detail']
        empty = jtos_df.empty
        too_many = len(jtos_df) > 200
        sample_df = jtos_df if not too_many else jtos_df.head(50)
        rows = []
        for _, row in sample_df.iterrows():
            rows.append({
                "ai_code": _row_value(row, 'ai_code'),
                "name": _row_value(row, 'name'),
                "address": _row_value(row, 'pn_address_line1'),
                "city": _row_value(row, 'pn_address_city'),
                "country": _row_value(row, 'pn_country'),
            })
        jtos_section = {
            "empty": empty,
            "too_many": too_many,
            "total": f"{len(jtos_df):,}",
            "rows": rows,
        }

    stoj_section = None
    if 'ai_s_to_j_detail' in additional_results:
        stoj_df = additional_results['ai_s_to_j_detail']
        empty = stoj_df.empty
        too_many = len(stoj_df) > 200
        sample_df = stoj_df if not too_many else stoj_df.head(50)
        rows = []
        for _, row in sample_df.iterrows():
            rows.append({
                "ai_code": _row_value(row, 'ai_code'),
                "name": _row_value(row, 'name'),
                "address": _row_value(row, 'pn_address_line1'),
                "city": _row_value(row, 'pn_address_city'),
                "country": _row_value(row, 'pn_country'),
            })
        stoj_section = {
            "empty": empty,
            "too_many": too_many,
            "total": f"{len(stoj_df):,}",
            "rows": rows,
        }

    template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "templates"))
    env = Environment(loader=FileSystemLoader(template_dir), autoescape=False)

    try:
        template = env.get_template("ai_report.md.j2")
    except TemplateNotFound as exc:
        raise FileNotFoundError("Template not found: ai_report.md.j2") from exc

    content = template.render(
        target_month=target_month,
        generated_on=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        env=args.env,
        stats_snapshot=stats_snapshot,
        diff_report=diff_rows,
        diff_totals=diff_totals,
        deletions_section=deletions_section,
        jtos_section=jtos_section,
        stoj_section=stoj_section,
        args=args,
        additional_query_names=list(additional_results.keys()),
    )

    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"Markdown report saved to {report_path}")
    return report_path
