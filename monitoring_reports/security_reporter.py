"""
Enhanced GitHub Security Alerts Comprehensive Reporter

This script takes a GitHub security alerts CSV export and generates detailed reports
with enriched information from the GitHub API.
"""
import argparse
import json
from pathlib import Path
from datetime import datetime
import pandas as pd

try:
    from cloudguard_reporter import CloudGuardReporter  # type: ignore
    CLOUDGUARD_AVAILABLE = True
except ImportError:
    CloudGuardReporter = None  # type: ignore
    CLOUDGUARD_AVAILABLE = False
    print("Warning: CloudGuard reporter not available. CloudGuard features will be disabled.")

class EnhancedGitHubSecurityReporter:
    def __init__(self, csv_file, enrichment_cache_path=None, use_gh_cli=False, gh_workers=4, rate_limit_delay=0.1):
        """Initialize the security reporter (token-based API path removed)."""
        self.csv_file = csv_file
        self.df = pd.read_csv(csv_file)
        self.rate_limit_delay = rate_limit_delay
        self.enriched_data = {}
        self.enrichment_cache_path = enrichment_cache_path
        self.use_gh_cli = use_gh_cli
        self.gh_workers = max(1, int(gh_workers))
        if self.enrichment_cache_path and Path(self.enrichment_cache_path).exists():
            try:
                with open(self.enrichment_cache_path, 'r', encoding='utf-8') as cf:
                    self.enriched_data = json.load(cf)
                    print(f"Loaded {len(self.enriched_data)} cached enrichment entries from {self.enrichment_cache_path}")
            except Exception as e:
                print(f"Warning: could not load enrichment cache: {e}")
        self._clean_data()
    
    def _clean_data(self):
        """Clean and standardize the CSV data"""
        # Standardize date columns and handle timezone issues
        date_columns = ['Created At', 'Updated At', 'Resolved At']
        for col in date_columns:
            if col in self.df.columns:
                # Convert to datetime and ensure timezone-naive for consistency
                self.df[col] = pd.to_datetime(self.df[col], errors='coerce', utc=True).dt.tz_localize(None)
        
        # Fill NaN values appropriately
        self.df['Package'] = self.df['Package'].fillna('Unknown')
        self.df['Ecosystem'] = self.df['Ecosystem'].fillna('Unknown')
        self.df['GHSA ID'] = self.df['GHSA ID'].fillna('')
    
    def filter_outstanding_issues(self):
        """Filter for outstanding (unresolved) issues"""
        outstanding = self.df[self.df['Resolved At'].isna()].copy()
        return outstanding
    
    # Token-based enrichment removed.
    
    def get_enriched_alert_summary(self, alert):
        """Get enriched summary for a specific alert"""
        cache_key = f"{alert['Repository']}#{alert['Alert Number']}#{alert['Tool']}"
        details = self.enriched_data.get(cache_key)
        
        if not details:
            return None
        
        summary = {
            'repository': alert['Repository'],
            'alert_number': alert['Alert Number'],
            'tool': alert['Tool'],
            'severity': alert['Severity']
        }
        
        if alert['Tool'] == 'dependabot':
            if 'security_advisory' in details:
                advisory = details['security_advisory']
                summary.update({
                    'cve_id': advisory.get('cve_id', 'N/A'),
                    'summary': advisory.get('summary', 'N/A'),
                    'description': advisory.get('description', 'N/A')[:200] + '...' if len(advisory.get('description', '')) > 200 else advisory.get('description', 'N/A'),
                    'published_at': advisory.get('published_at', 'N/A'),
                    'updated_at': advisory.get('updated_at', 'N/A')
                })
            
            if 'dependency' in details:
                dependency = details['dependency']
                summary.update({
                    'package_name': dependency.get('package', {}).get('name', 'N/A'),
                    'package_ecosystem': dependency.get('package', {}).get('ecosystem', 'N/A'),
                    'manifest_path': dependency.get('manifest_path', 'N/A'),
                    'scope': dependency.get('scope', 'N/A')
                })
        
        elif alert['Tool'] in ['code_scanning', 'CodeQL']:
            if 'rule' in details:
                rule = details['rule']
                summary.update({
                    'rule_id': rule.get('id', 'N/A'),
                    'rule_name': rule.get('name', 'N/A'),
                    'rule_description': rule.get('description', 'N/A')[:200] + '...' if len(rule.get('description', '')) > 200 else rule.get('description', 'N/A')
                })
            
            if 'most_recent_instance' in details:
                instance = details['most_recent_instance']
                summary.update({
                    'location': f"{instance.get('location', {}).get('path', 'N/A')}:{instance.get('location', {}).get('start_line', 'N/A')}",
                    'message': instance.get('message', {}).get('text', 'N/A')[:100] + '...' if len(instance.get('message', {}).get('text', '')) > 100 else instance.get('message', {}).get('text', 'N/A')
                })
        
        return summary

    def enrich_with_gh_cli(self, max_alerts=None):
        """Enrich alerts using the GitHub CLI (gh) with optional parallelization & caching."""
        import subprocess
        import json as _json
        import shutil
        from concurrent.futures import ThreadPoolExecutor, as_completed
        if not shutil.which('gh'):
            print("gh CLI not found in PATH; cannot perform CLI enrichment.")
            return
        outstanding = self.filter_outstanding_issues()
        alerts_to_process = outstanding.head(max_alerts) if max_alerts else outstanding
        print(f"Enriching {len(alerts_to_process)} alerts via gh CLI using {self.gh_workers} worker(s)...")

        def need_enrich(alert_row):
            cache_key = f"{alert_row['Repository']}#{alert_row['Alert Number']}#{alert_row['Tool']}"
            return cache_key not in self.enriched_data

        to_fetch = [alert for _, alert in alerts_to_process.iterrows() if need_enrich(alert)]
        print(f"  {len(to_fetch)} alerts require new enrichment (cached: {len(alerts_to_process)-len(to_fetch)})")

        def fetch(alert):
            repo = alert['Repository']
            num = alert['Alert Number']
            tool = alert['Tool']
            if tool == 'dependabot':
                endpoint = f"repos/{repo}/dependabot/alerts/{num}"
            elif tool in ['code_scanning', 'CodeQL']:
                endpoint = f"repos/{repo}/code-scanning/alerts/{num}"
            elif tool == 'secret_scanning':
                endpoint = f"repos/{repo}/secret-scanning/alerts/{num}"
            else:
                return None, None
            try:
                result = subprocess.run(['gh', 'api', endpoint], capture_output=True, text=True, timeout=25)
                if result.returncode == 0:
                    data = _json.loads(result.stdout)
                    return f"{repo}#{num}#{tool}", data
                else:
                    return None, f"gh api error {result.returncode} for {endpoint}: {result.stderr.strip()}"
            except Exception as e:
                return None, f"Exception for {endpoint}: {e}"

        if self.gh_workers > 1 and len(to_fetch) > 1:
            errors = 0
            with ThreadPoolExecutor(max_workers=self.gh_workers) as ex:
                futures = {ex.submit(fetch, alert): alert for alert in to_fetch}
                for i, fut in enumerate(as_completed(futures), 1):
                    key, result = fut.result()
                    if key and result:
                        self.enriched_data[key] = result
                    elif result and errors < 5:  # limited error spam
                        errors += 1
                        print(result)
                    if i % 25 == 0:
                        print(f"  Progress: {i}/{len(to_fetch)} fetched")
        else:
            for idx, alert in enumerate(to_fetch, 1):
                key, result = fetch(alert)
                if key and result:
                    self.enriched_data[key] = result
                elif result and idx <= 5:
                    print(result)
                if idx % 25 == 0:
                    print(f"  Progress: {idx}/{len(to_fetch)} fetched")

        print(f"CLI enrichment complete. Total enriched entries: {len(self.enriched_data)}")
        if self.enrichment_cache_path:
            try:
                with open(self.enrichment_cache_path, 'w', encoding='utf-8') as cf:
                    json.dump(self.enriched_data, cf, indent=2)
                print(f"Cache written to {self.enrichment_cache_path}")
            except Exception as e:
                print(f"Warning: failed to write enrichment cache: {e}")
    
    def generate_comprehensive_report(self, output_file='security_report.md', include_enriched=True, severity_filter=None, summary_only=False, include_recommendations=False):
        """Generate a comprehensive security report (gh CLI enrichment only)."""
        outstanding = self.filter_outstanding_issues().copy()
        if severity_filter:
            outstanding = outstanding[outstanding['Severity'].isin(severity_filter)]

        report = []
        report.append("# GitHub Security Alerts - Outstanding Issues Report")
        report.append(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Data source: {self.csv_file}")
        report.append(f"Enrichment entries: {len(self.enriched_data)}")
        if severity_filter:
            report.append(f"Severity filter: {', '.join(severity_filter)}")
        report.append("")

        total_outstanding = len(self.filter_outstanding_issues())
        filtered_outstanding = len(outstanding)
        if severity_filter:
            report.append(f"- **Total Outstanding Alerts**: {total_outstanding}")
            report.append(f"- **Filtered Alerts (selected severities)**: {filtered_outstanding}")
        else:
            report.append(f"- **Total Outstanding Alerts**: {filtered_outstanding}")

        severity_counts = outstanding['Severity'].value_counts()
        for severity, count in severity_counts.items():
            report.append(f"- **{str(severity).title()}**: {count}")

        now = pd.Timestamp.now().tz_localize(None)
        outstanding['days_open'] = (now - pd.to_datetime(outstanding['Created At'], errors='coerce')).dt.days
        aged_30 = outstanding[outstanding['days_open'] > 30]
        aged_90 = outstanding[outstanding['days_open'] > 90]
        report.append(f"- **Aged > 30 days**: {len(aged_30)}")
        report.append(f"- **Aged > 90 days**: {len(aged_90)}\n")

        report.append("## Analysis by Security Tool")
        for tool, count in outstanding['Tool'].value_counts().items():
            report.append(f"- **{tool}**: {count} alerts")
        report.append("")

        critical_alerts = outstanding[outstanding['Severity'] == 'critical']
        if len(critical_alerts) > 0:
            report.append("## Repositories With Critical Alerts")
            for repo, count in critical_alerts['Repository'].value_counts().items():
                report.append(f"- **{repo}**: {count} critical")
            report.append("")

        report.append("## Most Affected Repositories")
        for repo, count in outstanding['Repository'].value_counts().head(10).items():
            report.append(f"- **{repo}**: {count} alerts")
        report.append("")

        secret_alerts = outstanding[outstanding['Tool'] == 'secret_scanning']
        if len(secret_alerts) > 0:
            report.append("## Secret Scanning Alerts")
            for repo, count in secret_alerts['Repository'].value_counts().items():
                crit = secret_alerts[(secret_alerts['Repository']==repo) & (secret_alerts['Severity']=='critical')]
                note = " (critical)" if len(crit) else ""
                report.append(f"- **{repo}**: {count} secrets{note}")
            report.append("")

        dependabot_alerts = outstanding[outstanding['Tool'] == 'dependabot']
        if len(dependabot_alerts) > 0:
            report.append("## Dependabot Vulnerabilities by Package")
            def severity_rank_list(sevs):
                order_map = {'critical':4,'high':3,'moderate':2,'medium':2,'low':1}
                uniq = sorted(set(sevs), key=lambda s: order_map.get(s,0), reverse=True)
                return ', '.join(uniq)
            pkg = dependabot_alerts.groupby(['Package','Ecosystem'])
            package_groups = pkg.agg(
                repositories=('Repository','nunique'),
                severities=('Severity', lambda x: severity_rank_list(x)),
                has_critical=('Severity', lambda x: any(s=='critical' for s in x)),
                ghsa=('GHSA ID','first')
            ).reset_index().sort_values(['has_critical','repositories'], ascending=[False, False])
            for _, row in package_groups.head(15).iterrows():
                report.append(f"- **{row['Ecosystem']}/{row['Package']}**: {row['repositories']} repositories")
                report.append(f"  - Severities: {row['severities']}")
                if row['ghsa']:
                    report.append(f"  - GHSA: {row['ghsa']}")
                report.append("")

        if not summary_only:
            critical_only = outstanding[outstanding['Severity'] == 'critical'].sort_values('days_open', ascending=False)
            report.append("## Critical Severity Alerts")
            report.append(f"*Showing {min(len(critical_only), 50)} critical alerts*\n")
            for _, alert in critical_only.head(50).iterrows():
                report.append(f"### {alert['Repository']} - Alert #{alert['Alert Number']}")
                report.append(f"- **Tool**: {alert['Tool']}")
                report.append("- **Severity**: CRITICAL")
                report.append(f"- **Age**: {alert['days_open']} days")
                report.append(f"- **Created**: {alert['Created At'].strftime('%Y-%m-%d')}")
                if include_enriched and self.enriched_data:
                    enriched = self.get_enriched_alert_summary(alert)
                    if enriched and alert['Tool']=='dependabot' and enriched.get('cve_id') and enriched.get('cve_id')!='N/A':
                        report.append(f"- **CVE**: {enriched['cve_id']}")
                explanation = self._get_vulnerability_explanation(alert)
                if explanation:
                    report.append(f"- **Explanation**: {explanation}")
                report.append("")

        if include_recommendations:
            report.append("## Recommendations")
            report.append("1. **Immediate Action Required**:")
            report.append(f"   - Address {len(critical_alerts)} critical alerts")
            report.append(f"   - Focus on {len(aged_90)} alerts older than 90 days")
            report.append("")
            report.append("2. **Process Improvements**:")
            report.append("   - Automate dependency updates")
            report.append("   - Weekly triage for critical & aged alerts")
            report.append("   - Integrate blocking gates for critical alerts")

        with open(output_file,'w', encoding='utf-8') as f:
            f.write('\n'.join(report))
        print(f"Comprehensive report generated: {output_file}")
        return '\n'.join(report)
    
    def generate_detailed_repository_report(self, output_file='detailed_repo_report.md', severity_filter=None, include_enriched=True, include_recommendations=False):
        """Generate a structured report split into Runtime, Development, Code Quality, and Secret Scanning sections."""
        df = self.filter_outstanding_issues().copy()
        if severity_filter:
            df = df[df['Severity'].isin(severity_filter)]

        # Normalize and derive
        if 'Dependency Scope' in df.columns:
            df['Dependency Scope'] = df['Dependency Scope'].fillna('UNKNOWN').str.upper()
        if 'Created At' in df.columns:
            created_series = pd.to_datetime(df['Created At'], errors='coerce')
            df['days_open'] = (pd.Timestamp.now().tz_localize(None) - created_series).dt.days  # type: ignore
        else:
            df['days_open'] = 0

        # Buckets
        runtime = df[(df['Tool'] == 'dependabot') & (df['Dependency Scope'] == 'RUNTIME')]
        development = df[(df['Tool'] == 'dependabot') & (df['Dependency Scope'] == 'DEVELOPMENT')]
        code_quality = df[df['Tool'].isin(['CodeQL', 'code_scanning'])]
        secret_scan = df[df['Tool'] == 'secret_scanning']

        severity_weight = {'critical': 5, 'high': 4, 'moderate': 3, 'medium': 3, 'low': 1}


        def sev_counts(sub):
            return {s: int(c) for s, c in sub['Severity'].value_counts().items()}

        report = []
        report.append('# GitHub Security Alerts - Detailed Repository Report (Segmented)')
        report.append(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Data source: {self.csv_file}")
        report.append(f"Enrichment entries: {len(self.enriched_data)}")
        if severity_filter:
            report.append(f"Severity filter: {', '.join(severity_filter)}")
        report.append('')

        # Master summary
        report.append('## Master Summary')
        report.append(f"- Total outstanding (after filters): {len(df)}")
        report.append(f"- Runtime dependency alerts: {len(runtime)}")
        report.append(f"- Development dependency alerts: {len(development)}")
        report.append(f"- Code quality/static analysis alerts: {len(code_quality)}")
        report.append(f"- Secret scanning alerts: {len(secret_scan)}")
        crit_runtime = len(runtime[runtime['Severity'].isin(['critical', 'high'])])
        crit_dev = len(development[development['Severity'].isin(['critical', 'high'])])
        crit_code = len(code_quality[code_quality['Severity'].isin(['critical', 'high'])])
        crit_secret = len(secret_scan[secret_scan['Severity'].isin(['critical', 'high'])])
        total_critical = sum([
            len(runtime[runtime['Severity']=='critical']),
            len(development[development['Severity']=='critical']),
            len(code_quality[code_quality['Severity']=='critical']),
            len(secret_scan[secret_scan['Severity']=='critical'])
        ])
        if total_critical > 0:
            report.append(f"- **CRITICAL ALERTS PRESENT**: runtime={len(runtime[runtime['Severity']=='critical'])} | dev={len(development[development['Severity']=='critical'])} | code={len(code_quality[code_quality['Severity']=='critical'])} | secrets={len(secret_scan[secret_scan['Severity']=='critical'])}")
        elif (crit_runtime + crit_dev + crit_code + crit_secret) > 0:
            report.append("- High-severity (but no critical) present")
        if crit_runtime:
            report.append(f"- ⚠️ Runtime critical/high: {crit_runtime}")
        if crit_dev:
            report.append(f"- 🔧 Dev critical/high: {crit_dev}")
        if crit_code:
            report.append(f"- 🔍 Code quality critical/high: {crit_code}")
        report.append('')

        def render_section(title, emoji, subset):
            report.append(f"## {emoji} {title}")
            if subset.empty:
                report.append('_No alerts in this category._')
                report.append('')
                return
            sc = sev_counts(subset)
            sev_line = ' | '.join([f"{k.title()}: {v}" for k, v in sc.items()])
            report.append(f"**Severity Breakdown**: {sev_line}")
            aged90 = (subset['days_open'] > 90).sum()
            if aged90:
                report.append(f"**Aged >90 days**: {aged90}")
            report.append('')
            repo_groups = []
            for repo, repo_alerts in subset.groupby('Repository'):
                has_critical = (repo_alerts['Severity'] == 'critical').any()
                repo_groups.append((repo, has_critical, repo_alerts))
            repo_groups.sort(key=lambda x: (not x[1], x[0].lower()))
            for repo, _, repo_alerts in repo_groups:
                # Sort: severity weight descending then days_open descending
                repo_alerts = repo_alerts.assign(_sev_weight=repo_alerts['Severity'].map(severity_weight)) 
                repo_alerts = repo_alerts.sort_values(['_sev_weight', 'days_open'], ascending=[False, False])
                repo_alerts = repo_alerts.drop(columns=['_sev_weight'])
                report.append(f"### {repo} ({len(repo_alerts)} alerts)")
                repo_sev = repo_alerts['Severity'].value_counts()
                repo_sev_line = ' | '.join([f"{s}:{c}" for s, c in repo_sev.items()])
                report.append(f"- Severities: {repo_sev_line}")
                oldest = int(repo_alerts['days_open'].max()) if len(repo_alerts) else 0
                report.append(f"- Oldest alert age: {oldest} days")
                report.append('')
                for _, alert in repo_alerts.iterrows():
                    line = f"* #{alert['Alert Number']} {alert['Severity'].upper()} - {alert['Tool']}"
                    if alert['Tool'] == 'dependabot' and pd.notna(alert.get('Package')):
                        line += f" | {alert.get('Ecosystem','')}/{alert.get('Package','')}"
                    line += f" | Age: {alert['days_open']}d"
                    if include_enriched and self.enriched_data:
                        enriched = self.get_enriched_alert_summary(alert)
                        if enriched and alert['Tool'] == 'dependabot' and enriched.get('cve_id') not in (None, 'N/A'):
                            line += f" | CVE: {enriched['cve_id']}"
                    report.append(line)
                report.append('')

        render_section('Runtime Dependency Vulnerabilities', '⚙️', runtime)
        render_section('Development Dependency Vulnerabilities', '🔧', development)
        render_section('Code Quality / Static Analysis Issues', '🔍', code_quality)
        render_section('Secret Scanning Issues', '🕵️', secret_scan)

        if include_recommendations:
            report.append('## Recommendations')
            recs = []
            if crit_runtime:
                recs.append(f"Address {crit_runtime} critical/high runtime vulns immediately")
            if crit_dev:
                recs.append(f"Prioritize {crit_dev} critical/high dev dependency vulns")
            if crit_code:
                recs.append(f"Review {crit_code} critical/high code quality issues")
            if len(secret_scan):
                recs.append(f"Remediate {len(secret_scan)} outstanding secret findings")
            recs.append('Establish weekly triage for >30d alerts')
            recs.append('Automate dependency update & pinning strategy')
            recs.append('Integrate blocking gates for critical/high in CI/CD')
            for i, r in enumerate(recs, 1):
                report.append(f"{i}. {r}")

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(report))
        print(f"Detailed repository report generated: {output_file}")
        return '\n'.join(report)
    
    def export_enriched_csv(self, output_file='enriched_security_alerts.csv'):
        """Export outstanding issues with optional enriched data"""
        df = self.filter_outstanding_issues().copy()
        try:
            df['Created At'] = pd.to_datetime(df['Created At'], errors='coerce', utc=True).dt.tz_localize(None)
            now_dt = pd.Timestamp.now().tz_localize(None)
            df['Days_Open'] = (now_dt - pd.to_datetime(df['Created At'], errors='coerce')).dt.days
        except Exception as e:
            print(f"Warning calculating days open: {e}")
            df['Days_Open'] = 0
        df['Risk_Score'] = df.apply(self._calculate_risk_score, axis=1)
        df['Priority'] = df.apply(self._assign_priority, axis=1)

        if self.enriched_data:
            cve_ids = []
            summaries = []
            packages = []
            locations = []
            rule_names = []
            for _, alert in df.iterrows():
                enriched = self.get_enriched_alert_summary(alert)
                if enriched:
                    cve_ids.append(enriched.get('cve_id','N/A'))
                    summaries.append(enriched.get('summary','N/A'))
                    packages.append(f"{enriched.get('package_ecosystem','N/A')}/{enriched.get('package_name','N/A')}")
                    locations.append(enriched.get('location','N/A'))
                    rule_names.append(enriched.get('rule_name','N/A'))
                else:
                    cve_ids.append('N/A')
                    summaries.append('N/A')
                    packages.append('N/A')
                    locations.append('N/A')
                    rule_names.append('N/A')
            df['CVE_ID'] = cve_ids
            df['Advisory_Summary'] = summaries
            df['Package_Details'] = packages
            df['Location'] = locations
            df['Rule_Name'] = rule_names

        base_cols = ['Repository', 'Alert Number', 'Tool', 'Severity', 'Days_Open', 'Priority', 'Risk_Score']
        enriched_cols = ['CVE_ID', 'Advisory_Summary', 'Package_Details', 'Location', 'Rule_Name'] if self.enriched_data else []
        remaining_cols = [c for c in df.columns if c not in base_cols + enriched_cols]
        export_cols = [c for c in base_cols + enriched_cols + remaining_cols if c in df.columns]
        df[export_cols].to_csv(output_file, index=False)
        print(f"Enriched CSV exported: {output_file}")
    
    def _calculate_risk_score(self, row):
        """Calculate a risk score based on severity and age"""
        severity_weights = {'critical': 10, 'high': 7, 'moderate': 4, 'medium': 4, 'low': 1}
        base_score = severity_weights.get(row['Severity'], 1)
        
        # Age penalty
        now = pd.Timestamp.now().tz_localize(None)  # Ensure timezone-naive
        days_open = (now - row['Created At']).days
        age_multiplier = 1 + (days_open / 100)  # Increase score by 1% per day
        
        return round(base_score * age_multiplier, 2)
    
    def _assign_priority(self, row):
        """Assign priority based on severity and other factors"""
        if row['Severity'] == 'critical':
            return 'P0 - Critical'
        elif row['Severity'] == 'high':
            return 'P1 - High'
        elif row['Severity'] in ['moderate', 'medium']:
            return 'P2 - Medium'
        else:
            return 'P3 - Low'
    
    def _get_vulnerability_explanation(self, alert):
        """Get a human-readable explanation of the vulnerability"""
        # Common GHSA explanations
        ghsa_explanations = {
            'GHSA-3xgq-45jj-v275': 'Command injection vulnerability in cross-spawn package that could allow arbitrary command execution.',
            'GHSA-9wv6-86v2-598j': 'Regular expression denial of service (ReDoS) in path-to-regexp that could cause application hang.',
            'GHSA-c2qf-rxjj-qqgw': 'Regular expression denial of service (ReDoS) in semver package affecting version parsing.',
            'GHSA-952p-6rrq-rcjv': 'Regular expression denial of service (ReDoS) in micromatch affecting glob pattern matching.',
            'GHSA-8hc4-vh64-cxmj': 'Server-side request forgery (SSRF) vulnerability in axios HTTP client library.',
            'GHSA-jr5f-v2jv-69x6': 'Axios vulnerability allowing potential data exposure through request/response interception.',
            'GHSA-3h5v-q93c-6h6q': 'WebSocket vulnerability in ws package that could lead to denial of service.',
            'GHSA-grv7-fg5c-xmjg': 'Regular expression denial of service (ReDoS) in braces package affecting brace expansion.',
            'GHSA-9c47-m6qq-7p4h': 'Prototype pollution vulnerability in json5 package allowing object modification.',
            'GHSA-crh6-fp67-6883': 'XML external entity (XXE) vulnerability in @xmldom/xmldom package.',
            'GHSA-67hx-6x53-jw92': 'Code injection vulnerability in @babel/traverse allowing arbitrary code execution.',
            'GHSA-v2mw-5mch-w8c5': 'Cross-site scripting (XSS) vulnerability in canvg SVG rendering library.',
            'GHSA-w532-jxjh-hjhj': 'Potential code injection in jsPDF library through malicious input.',
            'GHSA-xvch-5gv4-984h': 'Prototype pollution in minimist argument parsing library.',
            'GHSA-2p57-rm9w-gvfp': 'Server-side request forgery (SSRF) vulnerability in ip package.',
            'GHSA-xffm-g5w8-qvg7': 'Potential code execution vulnerability in ESLint plugin kit.',
            'GHSA-rx28-r23p-2qc3': 'Potential security issue in AWS CDK library affecting cloud deployments.',
            'GHSA-78wr-2p64-hpwj': 'Path traversal vulnerability in commons-io affecting file operations.',
            'GHSA-rgv9-q543-rqg4': 'Deserialization vulnerability in Jackson databind library.',
            'GHSA-jjjh-jjxp-wpff': 'Another deserialization issue in Jackson databind with different attack vectors.',
            'GHSA-3vqj-43w4-2q58': 'Denial of service vulnerability in org.json library.',
            'GHSA-4jq9-2xhw-jpx7': 'Additional denial of service issue in org.json with stack overflow potential.',
        }
        
        # CodeQL rule explanations
        codeql_explanations = {
            'js/clear-text-logging': 'Sensitive information is being logged in plain text, potentially exposing credentials or personal data.',
            'js/functionality-from-untrusted-source': 'Code is loading functionality from untrusted sources, creating potential security risks.',
            'js/unsafe-external-link': 'External links are not properly validated, potentially leading to phishing or malware.',
            'java/concatenated-command-line': 'Command line arguments are concatenated unsafely, potentially allowing command injection.',
            'java/comparison-with-wider-type': 'Numeric comparisons with wider types that could lead to unexpected behavior.',
        }
        
        # Package-specific explanations
        package_explanations = {
            'cross-spawn': 'A library for spawning child processes that has known command injection vulnerabilities.',
            'path-to-regexp': 'A utility for converting path strings to regular expressions with known ReDoS issues.',
            'semver': 'Semantic version parsing library with regular expression denial of service vulnerabilities.',
            'micromatch': 'Glob matching library with regular expression performance issues.',
            'axios': 'Popular HTTP client with various security issues in different versions.',
            'ws': 'WebSocket library with denial of service vulnerabilities.',
            'json5': 'JSON parser with prototype pollution issues.',
            '@xmldom/xmldom': 'XML parsing library vulnerable to XXE attacks.',
            '@babel/traverse': 'Babel AST traversal utility with code injection risks.',
        }
        
        # Try to get explanation from GHSA ID first
        if pd.notna(alert.get('GHSA ID')) and alert['GHSA ID'] in ghsa_explanations:
            return ghsa_explanations[alert['GHSA ID']]
        
        # Try CodeQL rule explanation
        if alert['Tool'] in ['CodeQL', 'code_scanning'] and pd.notna(alert.get('CodeQL Rule')):
            rule = alert['CodeQL Rule']
            if rule in codeql_explanations:
                return codeql_explanations[rule]
        
        # Try package-based explanation
        if alert['Tool'] == 'dependabot' and pd.notna(alert.get('Package')):
            package = alert['Package']
            if package in package_explanations:
                return package_explanations[package]
        
        # Generic explanations based on tool
        if alert['Tool'] == 'dependabot':
            return 'Dependency vulnerability detected. Update to the latest secure version of this package.'
        elif alert['Tool'] in ['CodeQL', 'code_scanning']:
            return 'Code quality or security issue detected by static analysis. Review and fix the identified code pattern.'
        elif alert['Tool'] == 'secret_scanning':
            return 'Potential secret or credential detected in code. Remove or rotate the exposed secret immediately.'
        
        return None


def main():
    parser = argparse.ArgumentParser(
        description='Enhanced GitHub Security Alerts Comprehensive Reporter',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic report with only critical/high alerts
  python enhanced_security_reporter.py alerts.csv
  
  # Comprehensive report with all severity levels
  python enhanced_security_reporter.py alerts.csv --assess-all
  
  # Generate per-repository detailed report
  python enhanced_security_reporter.py alerts.csv --detailed-repo-report
  
  # Custom output directory and multiple report types
  python enhanced_security_reporter.py alerts.csv --assess-all --detailed-repo-report --output-dir ./security_reports
  
  # Include CloudGuard findings with GitHub alerts
  python enhanced_security_reporter.py alerts.csv --detailed-repo-report --cloudguard-csv cloudguard_findings.csv --cloudguard-environments prod nonprod
  
  # CloudGuard reports organized by alert type
  python enhanced_security_reporter.py alerts.csv --cloudguard-csv cloudguard_findings.csv --cloudguard-group-by alert
        """
    )
    
    parser.add_argument('csv_file', help='Path to GitHub security alerts CSV file')
    
    # Enrichment options (gh CLI only)
    parser.add_argument('--enrichment-cache', help='Path to JSON cache file for gh CLI enrichment results')
    parser.add_argument('--gh-workers', type=int, default=4, help='Number of parallel gh API workers (default: 4)')
    parser.add_argument('--skip-enrichment', action='store_true', help='Skip gh CLI enrichment step')
    
    # Report content options
    parser.add_argument('--assess-all', action='store_true', 
                       help='Assess all severity levels (default: focus on critical/high only)')
    parser.add_argument('--min-severity', choices=['low', 'medium', 'moderate', 'high', 'critical'], 
                       default='high', help='Minimum severity level to include in detailed analysis (default: high)')
    
    # Report type options
    parser.add_argument('--detailed-repo-report', action='store_true', 
                       help='Generate detailed per-repository report')
    parser.add_argument('--summary-only', action='store_true', 
                       help='Generate only summary report (skip detailed critical/high analysis)')
    parser.add_argument('--include-recommendations', action='store_true',
                       help='Include recommendations sections (default: off)')
    
    # Output options
    parser.add_argument('--output-dir', default='.', help='Output directory for reports')
    parser.add_argument('--output-prefix', default='enhanced_security', 
                       help='Prefix for output files (default: enhanced_security)')
    
    # Filtering options
    parser.add_argument('--max-age-days', type=int, 
                       help='Only include alerts older than specified days')
    parser.add_argument('--repository-filter', 
                       help='Only include repositories matching this pattern (regex supported)')
    
    # CloudGuard options
    if CLOUDGUARD_AVAILABLE:
        parser.add_argument('--cloudguard-csv', 
                           help='Path to CloudGuard findings CSV file for additional reporting')
        parser.add_argument('--cloudguard-environments', nargs='*', 
                           choices=['prod', 'nonprod', 'all'], default=['all'],
                           help='CloudGuard environments to report on (default: all)')
        parser.add_argument('--cloudguard-group-by', choices=['asset', 'alert'], 
                default='asset', help='Group CloudGuard findings by asset or alert type (default: asset)')
        parser.add_argument('--cloudguard-account-filter',
                help='Regex or glob pattern to filter CloudGuard Cloud Account Name (e.g., ap-* or ^ap-prod)')
        parser.add_argument('--cloudguard-include-recommendations', action='store_true',
                           help='Include recommendations section in CloudGuard report (default: off)')
        parser.add_argument('--cloudguard-extra-tiers', nargs='*', choices=['B','C'],
                    help='Include extra CloudGuard grouping tiers (B=Compliance Section, C=Stack)')
        parser.add_argument('--cloudguard-lower-priority', action='store_true',
                    help='Include optional lower priority (Medium/Low/Info) CloudGuard section')
        parser.add_argument('--cloudguard-export-csv', metavar='PATH',
                    help='Export processed CloudGuard normalized CSV to PATH')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.assess_all and args.min_severity != 'high':
        print("Warning: --assess-all overrides --min-severity setting")
    
    # Initialize reporter (token path removed)
    reporter = EnhancedGitHubSecurityReporter(
        args.csv_file,
        enrichment_cache_path=args.enrichment_cache,
        use_gh_cli=not args.skip_enrichment,
        gh_workers=args.gh_workers
    )
    
    # Apply filters if specified
    if args.repository_filter:
        # Support both regex and simple glob-like wildcards (*, ?) for repository filtering.
        import re
        import fnmatch
        repo_pattern_input = args.repository_filter.strip()
        original_count = len(reporter.df)

        # Decide whether to treat as glob: if it contains * or ? and is not a pure regex group (anchored with ^)
        is_glob = any(ch in repo_pattern_input for ch in ['*', '?']) and not repo_pattern_input.startswith('^')

        def match_repo(repo_full: str) -> bool:
            if not isinstance(repo_full, str):
                return False
            repo_name = repo_full.split('/')[-1]
            if is_glob:
                return (fnmatch.fnmatchcase(repo_full.lower(), repo_pattern_input.lower()) or
                        fnmatch.fnmatchcase(repo_name.lower(), repo_pattern_input.lower()))
            try:
                pattern = re.compile(repo_pattern_input, re.IGNORECASE)
                return bool(pattern.search(repo_full) or pattern.search(repo_name))
            except re.error:
                return repo_pattern_input.lower() in repo_full.lower() or repo_pattern_input.lower() in repo_name.lower()

        reporter.df = reporter.df[reporter.df['Repository'].apply(match_repo)]
        print(f"Repository filter applied ('{repo_pattern_input}'): {len(reporter.df)} alerts remaining (was {original_count})")
    
    if args.max_age_days:
        original_count = len(reporter.df)
        cutoff_date = pd.Timestamp.now().tz_localize(None) - pd.Timedelta(days=args.max_age_days)
        reporter.df = reporter.df[reporter.df['Created At'] < cutoff_date]
        print(f"Age filter applied: {len(reporter.df)} alerts remaining (was {original_count})")
    
    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)
    
    # Enrich via gh CLI if requested
    if not args.skip_enrichment:
        reporter.enrich_with_gh_cli()
    
    # Determine severity filter
    if args.assess_all:
        severity_filter = None
    else:
        severity_order = ['low', 'medium', 'moderate', 'high', 'critical']
        min_index = severity_order.index(args.min_severity)
        severity_filter = severity_order[min_index:]
    
    # Generate reports
    report_file = output_dir / f'{args.output_prefix}_report.md'
    csv_file = output_dir / f'{args.output_prefix}_alerts.csv'
    
    reporter.generate_comprehensive_report(
        str(report_file), 
        include_enriched=not args.skip_enrichment,
        severity_filter=severity_filter,
        summary_only=args.summary_only,
        include_recommendations=args.include_recommendations
    )
    reporter.export_enriched_csv(str(csv_file))
    
    print(f"\nReports generated in {output_dir}:")
    print(f"  - {report_file}")
    print(f"  - {csv_file}")
    
    # Generate detailed per-repository report if requested
    if args.detailed_repo_report:
        detailed_report_file = output_dir / f'{args.output_prefix}_detailed_by_repo.md'
        reporter.generate_detailed_repository_report(
            str(detailed_report_file),
            severity_filter=severity_filter,
            include_enriched=not args.skip_enrichment,
            include_recommendations=args.include_recommendations
        )
        print(f"  - {detailed_report_file}")
    
    # Generate CloudGuard reports if requested and available
    if CLOUDGUARD_AVAILABLE and CloudGuardReporter is not None and hasattr(args, 'cloudguard_csv') and args.cloudguard_csv:
        if not Path(args.cloudguard_csv).exists():
            print(f"Warning: CloudGuard CSV file {args.cloudguard_csv} not found, skipping CloudGuard reports")
        else:
            print(f"\nGenerating CloudGuard reports from {args.cloudguard_csv}...")
            try:
                if not CLOUDGUARD_AVAILABLE or CloudGuardReporter is None:
                    print("CloudGuardReporter not available; skipping CloudGuard processing.")
                    return
                cg_reporter = CloudGuardReporter(args.cloudguard_csv)

                # Optional CloudGuard account filter
                if hasattr(args, 'cloudguard_account_filter') and args.cloudguard_account_filter:
                    import re
                    import fnmatch
                    acct_pattern = args.cloudguard_account_filter.strip()
                    is_glob = any(ch in acct_pattern for ch in ['*', '?']) and not acct_pattern.startswith('^')

                    def match_acct(name: str) -> bool:
                        if not isinstance(name, str):
                            return False
                        if is_glob:
                            return fnmatch.fnmatchcase(name.lower(), acct_pattern.lower())
                        try:
                            pat = re.compile(acct_pattern, re.IGNORECASE)
                            return bool(pat.search(name))
                        except re.error:
                            return acct_pattern.lower() in name.lower()

                    df_local = getattr(cg_reporter, 'df', None)
                    if isinstance(df_local, pd.DataFrame) and 'Cloud Account Name' in df_local.columns:
                        before_cnt = len(df_local)
                        cg_reporter.df = df_local[df_local['Cloud Account Name'].apply(match_acct)]
                        print(f"CloudGuard account filter applied ('{acct_pattern}'): {len(cg_reporter.df)} findings (was {before_cnt})")
                    else:
                        print("Warning: CloudGuard data frame not loaded or missing 'Cloud Account Name' column; skipping account filter")

                for environment in args.cloudguard_environments:
                    cg_report_file = output_dir / f'{args.output_prefix}_cloudguard_{environment}_{args.cloudguard_group_by}.md'
                    if hasattr(cg_reporter, 'generate_environment_report'):
                        cg_reporter.generate_environment_report(
                            environment=environment,
                            group_by=args.cloudguard_group_by,
                            output_file=str(cg_report_file),
                            include_recommendations=args.cloudguard_include_recommendations,
                            extra_tiers=args.cloudguard_extra_tiers,
                            lower_priority_section=args.cloudguard_lower_priority
                        )
                        print(f"  - {cg_report_file}")

                if getattr(args, 'cloudguard_export_csv', None):
                    cg_reporter.export_processed_csv(args.cloudguard_export_csv)

            except Exception as e:
                print(f"Error generating CloudGuard reports: {e}")


if __name__ == "__main__":
    main()
