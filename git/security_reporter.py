"""
Enhanced GitHub Security Alerts Comprehensive Reporter

This script takes a GitHub security alerts CSV export and generates detailed reports
with enriched information from the GitHub API.
"""
import os
import argparse
import time
from pathlib import Path
import json
from datetime import datetime, timedelta
import pandas as pd
import requests

try:
    from cloudguard_reporter import CloudGuardReporter
    CLOUDGUARD_AVAILABLE = True
except ImportError:
    CLOUDGUARD_AVAILABLE = False
    print("Warning: CloudGuard reporter not available. CloudGuard features will be disabled.")

class EnhancedGitHubSecurityReporter:
    def __init__(self, csv_file, github_token=None, rate_limit_delay=0.1):
        """
        Initialize the security reporter
        
        Args:
            csv_file (str): Path to the GitHub security alerts CSV
            github_token (str): GitHub personal access token for API calls
            rate_limit_delay (float): Delay between API calls to avoid rate limiting
        """
        self.csv_file = csv_file
        self.df = pd.read_csv(csv_file)
        self.github_token = github_token
        self.rate_limit_delay = rate_limit_delay
        self.headers = {
            'Authorization': f'token {github_token}' if github_token else None,
            'Accept': 'application/vnd.github.v3+json'
        }
        self.enriched_data = {}
        
        # Clean up data
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
    
    def fetch_alert_details(self, alert):
        """
        Fetch detailed information for a specific alert using GitHub API
        """
        if not self.github_token:
            return None
        
        repo_name = alert['Repository']
        alert_number = alert['Alert Number']
        tool = alert['Tool']
        
        # Check cache first
        cache_key = f"{repo_name}#{alert_number}#{tool}"
        if cache_key in self.enriched_data:
            return self.enriched_data[cache_key]
        
        # Different endpoints for different tools
        if tool == 'dependabot':
            url = f"https://api.github.com/repos/{repo_name}/dependabot/alerts/{alert_number}"
        elif tool == 'code_scanning' or tool == 'CodeQL':
            url = f"https://api.github.com/repos/{repo_name}/code-scanning/alerts/{alert_number}"
        elif tool == 'secret_scanning':
            url = f"https://api.github.com/repos/{repo_name}/secret-scanning/alerts/{alert_number}"
        else:
            return None
        
        try:
            time.sleep(self.rate_limit_delay)  # Rate limiting
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                self.enriched_data[cache_key] = data
                return data
            elif response.status_code == 404:
                print(f"Alert {alert_number} not found in {repo_name}")
            elif response.status_code == 403:
                print(f"Access denied for {repo_name} - check permissions")
            else:
                print(f"API error {response.status_code} for {repo_name}/{alert_number}")
        except Exception as e:
            print(f"Error fetching alert details for {repo_name}/{alert_number}: {e}")
        
        return None
    
    def enrich_outstanding_alerts(self, max_alerts=None):
        """
        Enrich outstanding alerts with detailed information from GitHub API
        
        Args:
            max_alerts (int): Maximum number of alerts to enrich (for testing)
        """
        if not self.github_token:
            print("Warning: No GitHub token provided. Skipping API enrichment.")
            return
        
        outstanding = self.filter_outstanding_issues()
        alerts_to_process = outstanding.head(max_alerts) if max_alerts else outstanding
        
        print(f"Enriching {len(alerts_to_process)} outstanding alerts with API data...")
        
        for idx, (_, alert) in enumerate(alerts_to_process.iterrows()):
            if idx % 10 == 0:
                print(f"Processed {idx}/{len(alerts_to_process)} alerts...")
            
            details = self.fetch_alert_details(alert)
            if details:
                # Store enriched data for later use
                cache_key = f"{alert['Repository']}#{alert['Alert Number']}#{alert['Tool']}"
                self.enriched_data[cache_key] = details
        
        print(f"Enrichment complete. {len(self.enriched_data)} alerts enriched.")
    
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
    
    def generate_comprehensive_report(self, output_file='security_report.md', include_enriched=True, severity_filter=None, summary_only=False):
        """Generate a comprehensive security report
        
        Args:
            output_file (str): Output file path
            include_enriched (bool): Include API-enriched data
            severity_filter (list): List of severities to include (None for all)
            summary_only (bool): Generate only summary, skip detailed analysis
        """
        outstanding = self.filter_outstanding_issues()
        
        # Apply severity filter if specified
        if severity_filter:
            outstanding = outstanding[outstanding['Severity'].isin(severity_filter)]
        
        report = []
        report.append("# GitHub Security Alerts - Outstanding Issues Report")
        report.append(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Data source: {self.csv_file}")
        report.append(f"API enrichment: {'Enabled' if self.github_token and include_enriched else 'Disabled'}")
        if severity_filter:
            report.append(f"Severity filter: {', '.join(severity_filter)}")
        report.append("")
        
        # Executive Summary
        report.append("## Executive Summary")
        total_outstanding = len(self.filter_outstanding_issues())  # Total before filtering
        filtered_outstanding = len(outstanding)  # After filtering
        
        if severity_filter:
            report.append(f"- **Total Outstanding Alerts**: {total_outstanding}")
            report.append(f"- **Filtered Alerts (selected severities)**: {filtered_outstanding}")
        else:
            report.append(f"- **Total Outstanding Alerts**: {filtered_outstanding}")
        
        severity_counts = outstanding['Severity'].value_counts()
        for severity, count in severity_counts.items():
            severity_str = str(severity).title() if severity is not None else 'Unknown'
            report.append(f"- **{severity_str}**: {count}")
        
        # Age Analysis
        now = pd.Timestamp.now().tz_localize(None)  # Ensure timezone-naive
        outstanding['days_open'] = (now - outstanding['Created At']).dt.days
        aged_30 = outstanding[outstanding['days_open'] > 30]
        aged_90 = outstanding[outstanding['days_open'] > 90]
        report.append(f"- **Aged > 30 days**: {len(aged_30)}")
        report.append(f"- **Aged > 90 days**: {len(aged_90)}\n")
        
        # Analysis by Tool
        report.append("## Analysis by Security Tool")
        tool_counts = outstanding['Tool'].value_counts()
        for tool, count in tool_counts.items():
            report.append(f"- **{tool}**: {count} alerts")
        report.append("")
        
        # Repository Analysis
        report.append("## Most Affected Repositories")
        repo_counts = outstanding['Repository'].value_counts()
        for repo, count in repo_counts.head(10).items():
            report.append(f"- **{repo}**: {count} alerts")
        report.append("")
        
        # Package Vulnerability Analysis (Dependabot)
        dependabot_alerts = outstanding[outstanding['Tool'] == 'dependabot']
        if len(dependabot_alerts) > 0:
            report.append("## Dependabot Vulnerabilities by Package")
            
            # Group by package
            package_groups = dependabot_alerts.groupby(['Package', 'Ecosystem']).agg({
                'Repository': 'nunique',
                'Severity': lambda x: ', '.join(sorted(x.unique())),
                'GHSA ID': 'first'
            }).reset_index()
            
            package_groups = package_groups.sort_values('Repository', ascending=False)
            
            for _, row in package_groups.head(15).iterrows():
                report.append(f"- **{row['Ecosystem']}/{row['Package']}**: {row['Repository']} repositories")
                report.append(f"  - Severities: {row['Severity']}")
                if row['GHSA ID']:
                    report.append(f"  - GHSA: {row['GHSA ID']}")
                report.append("")
        
        # Skip detailed analysis if summary_only is True
        if not summary_only:
            # Critical and High Severity Details (or filtered severity)
            display_severities = severity_filter if severity_filter else ['critical', 'high']
            critical_high = outstanding[outstanding['Severity'].isin(display_severities)]
            critical_high = critical_high.sort_values(['Severity', 'days_open'], ascending=[False, False])
            
            severity_text = '/'.join([s.title() for s in display_severities])
            report.append(f"## {severity_text} Severity Alerts")
            report.append(f"*Showing {min(len(critical_high), 50)} most critical alerts*\n")
            
            for _, alert in critical_high.head(50).iterrows():
                report.append(f"### {alert['Repository']} - Alert #{alert['Alert Number']}")
                report.append(f"- **Tool**: {alert['Tool']}")
                report.append(f"- **Severity**: {alert['Severity'].upper()}")
                report.append(f"- **Age**: {alert['days_open']} days")
                report.append(f"- **Created**: {alert['Created At'].strftime('%Y-%m-%d')}")
                
                # Add enriched data if available
                if include_enriched and self.github_token:
                    enriched = self.get_enriched_alert_summary(alert)
                    if enriched:
                        if alert['Tool'] == 'dependabot':
                            if enriched.get('cve_id') != 'N/A':
                                report.append(f"- **CVE**: {enriched['cve_id']}")
                            if enriched.get('summary') != 'N/A':
                                report.append(f"- **Summary**: {enriched['summary']}")
                            if enriched.get('package_name') != 'N/A':
                                report.append(f"- **Package**: {enriched['package_ecosystem']}/{enriched['package_name']}")
                            if enriched.get('manifest_path') != 'N/A':
                                report.append(f"- **Manifest**: {enriched['manifest_path']}")
                        
                        elif alert['Tool'] in ['code_scanning', 'CodeQL']:
                            if enriched.get('rule_name') != 'N/A':
                                report.append(f"- **Rule**: {enriched['rule_name']}")
                            if enriched.get('location') != 'N/A':
                                report.append(f"- **Location**: {enriched['location']}")
                            if enriched.get('message') != 'N/A':
                                report.append(f"- **Message**: {enriched['message']}")
                
                # Fallback to CSV data if no enriched data
                else:
                    if alert['Tool'] == 'dependabot' and pd.notna(alert['Package']):
                        report.append(f"- **Package**: {alert['Ecosystem']}/{alert['Package']}")
                        if pd.notna(alert['GHSA ID']):
                            report.append(f"- **GHSA**: {alert['GHSA ID']}")
                
                # Add vulnerability explanation
                explanation = self._get_vulnerability_explanation(alert)
                if explanation:
                    report.append(f"- **Explanation**: {explanation}")
                
                report.append("")
        
        # Recommendations
        report.append("## Recommendations")
        report.append("1. **Immediate Action Required**:")
        
        if severity_filter:
            critical_high_count = len(outstanding[outstanding['Severity'].isin(['critical', 'high'])])
            report.append(f"   - Address {critical_high_count} critical/high severity alerts")
        else:
            report.append(f"   - Address {len(outstanding)} alerts")
            
        report.append(f"   - Focus on {len(aged_90)} alerts older than 90 days")
        report.append("")
        report.append("2. **Package Management**:")
        if len(dependabot_alerts) > 0:
            top_packages = dependabot_alerts['Package'].value_counts().head(3)
            for package, count in top_packages.items():
                report.append(f"   - Update {package} ({count} alerts)")
        report.append("")
        report.append("3. **Repository Prioritization**:")
        top_repos = outstanding['Repository'].value_counts().head(3)
        for repo, count in top_repos.items():
            report.append(f"   - {repo}: {count} alerts")
        report.append("")
        report.append("4. **Process Improvements**:")
        report.append("   - Implement automated dependency updates")
        report.append("   - Set up alert notifications for critical issues")
        report.append("   - Regular security review cadence")
        
        # Write report
        with open(output_file, 'w') as f:
            f.write('\n'.join(report))
        
        print(f"Comprehensive report generated: {output_file}")
        return '\n'.join(report)
    
    def generate_detailed_repository_report(self, output_file='detailed_repo_report.md', severity_filter=None, include_enriched=True):
        """Generate a detailed per-repository report showing all issues for each repository
        
        Args:
            output_file (str): Output file path
            severity_filter (list): List of severities to include (None for all)
            include_enriched (bool): Include API-enriched data
        """
        outstanding = self.filter_outstanding_issues()
        
        # Apply severity filter if specified
        if severity_filter:
            outstanding = outstanding[outstanding['Severity'].isin(severity_filter)]
        
        # Group by repository
        repos = outstanding.groupby('Repository')
        
        report = []
        report.append("# GitHub Security Alerts - Detailed Repository Report")
        report.append(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Data source: {self.csv_file}")
        report.append(f"API enrichment: {'Enabled' if self.github_token and include_enriched else 'Disabled'}")
        if severity_filter:
            report.append(f"Severity filter: {', '.join(severity_filter)}")
        report.append("")
        
        # Check for critical/high runtime issues and add prominent warning
        runtime_critical_high = outstanding[
            (outstanding['Tool'] == 'dependabot') & 
            (outstanding['Dependency Scope'] == 'RUNTIME') & 
            (outstanding['Severity'].isin(['critical', 'high']))
        ]
        
        if len(runtime_critical_high) > 0:
            report.append("# ⚠️ **URGENT: PRODUCTION RUNTIME VULNERABILITIES DETECTED** ⚠️")
            report.append("")
            report.append("## 🚨 **IMMEDIATE ACTION REQUIRED** 🚨")
            report.append("")
            report.append("**Critical and High severity vulnerabilities have been detected in RUNTIME dependencies.**")
            report.append("**These affect your production environment and require immediate attention.**")
            report.append("")
            
            # Group runtime issues by repository
            runtime_by_repo = runtime_critical_high.groupby('Repository').size().sort_index()  # Sort alphabetically
            
            report.append("### **Affected Repositories (Production Impact):**")
            report.append("")
            for repo, count in runtime_by_repo.items():
                severity_breakdown = runtime_critical_high[runtime_critical_high['Repository'] == repo]['Severity'].value_counts()
                severity_text = []
                if 'critical' in severity_breakdown:
                    severity_text.append(f"**{severity_breakdown['critical']} CRITICAL**")
                if 'high' in severity_breakdown:
                    severity_text.append(f"**{severity_breakdown['high']} HIGH**")
                
                report.append(f"- **{repo}**: {count} runtime issues ({', '.join(severity_text)})")
            
            report.append("")
            report.append("### **⚡ Priority Actions:**")
            report.append("1. **Deploy patches immediately** for critical runtime vulnerabilities")
            report.append("2. **Review and update** affected production dependencies")
            report.append("3. **Monitor logs** for potential exploitation attempts")
            report.append("4. **Consider temporary mitigations** if patches are not immediately available")
            report.append("")
            report.append("---")
            report.append("")
        
        # Check for critical/high development issues and add warning
        dev_critical_high = outstanding[
            (outstanding['Tool'] == 'dependabot') & 
            (outstanding['Dependency Scope'] == 'DEVELOPMENT') & 
            (outstanding['Severity'].isin(['critical', 'high']))
        ]
        
        if len(dev_critical_high) > 0:
            report.append("# 🔧 **ATTENTION: DEVELOPMENT ENVIRONMENT VULNERABILITIES** 🔧")
            report.append("")
            report.append("## 💻 **Development Security Issues Detected**")
            report.append("")
            report.append("**Critical and High severity vulnerabilities have been detected in DEVELOPMENT dependencies.**")
            report.append("**While these don't directly affect production, they pose risks during development and build processes.**")
            report.append("")
            
            # Group development issues by repository
            dev_by_repo = dev_critical_high.groupby('Repository').size().sort_index()  # Sort alphabetically
            
            # Check if there are any critical development issues to highlight them
            dev_critical = dev_critical_high[dev_critical_high['Severity'] == 'critical']
            if len(dev_critical) > 0:
                report.append("### **🚨 Critical Development Issues (Highest Priority):**")
                report.append("")
                dev_critical_by_repo = dev_critical.groupby('Repository').size().sort_index()  # Sort alphabetically
                for repo, count in dev_critical_by_repo.items():
                    severity_breakdown = dev_critical[dev_critical['Repository'] == repo]['Severity'].value_counts()
                    report.append(f"- **{repo}**: {count} **CRITICAL** development issues")
                report.append("")
            
            report.append("### **Affected Repositories (Development Impact):**")
            report.append("")
            for repo, count in dev_by_repo.items():
                severity_breakdown = dev_critical_high[dev_critical_high['Repository'] == repo]['Severity'].value_counts()
                severity_text = []
                if 'critical' in severity_breakdown:
                    severity_text.append(f"**{severity_breakdown['critical']} CRITICAL**")
                if 'high' in severity_breakdown:
                    severity_text.append(f"**{severity_breakdown['high']} HIGH**")
                
                report.append(f"- **{repo}**: {count} development issues ({', '.join(severity_text)})")
            
            report.append("")
            report.append("### **🛠️ Development Security Actions:**")
            report.append("1. **Update development dependencies** to resolve vulnerabilities")
            report.append("2. **Review build and CI/CD pipelines** for potential exposure")
            report.append("3. **Audit developer workstations** that may be affected")
            report.append("4. **Consider dependency pinning** for critical development tools")
            report.append("5. **Implement security scanning** in development workflows")
            report.append("")
            report.append("---")
            report.append("")
        
        # Check for critical/high CodeQL issues and add warning
        codeql_critical_high = outstanding[
            (outstanding['Tool'].isin(['CodeQL', 'code_scanning'])) & 
            (outstanding['Severity'].isin(['critical', 'high']))
        ]
        
        if len(codeql_critical_high) > 0:
            report.append("# 🔍 **ATTENTION: CODE QUALITY & SECURITY ISSUES DETECTED** 🔍")
            report.append("")
            report.append("## 📊 **Static Analysis Security Issues Detected**")
            report.append("")
            report.append("**Critical and High severity code quality and security issues have been detected by static analysis.**")
            report.append("**These indicate potential security vulnerabilities, code quality issues, or anti-patterns in your source code.**")
            report.append("")
            
            # Group CodeQL issues by repository
            codeql_by_repo = codeql_critical_high.groupby('Repository').size().sort_index()  # Sort alphabetically
            
            # Check if there are any critical CodeQL issues to highlight them
            codeql_critical = codeql_critical_high[codeql_critical_high['Severity'] == 'critical']
            if len(codeql_critical) > 0:
                report.append("### **🚨 Critical Code Issues (Highest Priority):**")
                report.append("")
                codeql_critical_by_repo = codeql_critical.groupby('Repository').size().sort_index()  # Sort alphabetically
                for repo, count in codeql_critical_by_repo.items():
                    severity_breakdown = codeql_critical[codeql_critical['Repository'] == repo]['Severity'].value_counts()
                    report.append(f"- **{repo}**: {count} **CRITICAL** code security issues")
                report.append("")
            
            report.append("### **Affected Repositories (Code Security Impact):**")
            report.append("")
            for repo, count in codeql_by_repo.items():
                severity_breakdown = codeql_critical_high[codeql_critical_high['Repository'] == repo]['Severity'].value_counts()
                severity_text = []
                if 'critical' in severity_breakdown:
                    severity_text.append(f"**{severity_breakdown['critical']} CRITICAL**")
                if 'high' in severity_breakdown:
                    severity_text.append(f"**{severity_breakdown['high']} HIGH**")
                
                report.append(f"- **{repo}**: {count} code issues ({', '.join(severity_text)})")
            
            report.append("")
            report.append("### **🛡️ Code Security Actions:**")
            report.append("1. **Review and fix identified code patterns** that pose security risks")
            report.append("2. **Audit sensitive code paths** highlighted by static analysis")
            report.append("3. **Implement secure coding practices** to prevent similar issues")
            report.append("4. **Consider security code review** for affected repositories")
            report.append("5. **Update development guidelines** based on identified patterns")
            report.append("")
            report.append("---")
            report.append("")
        
        # Summary
        total_repos = len(repos)
        total_alerts = len(outstanding)
        report.append("## Summary")
        report.append(f"- **Repositories with alerts**: {total_repos}")
        report.append(f"- **Total alerts**: {total_alerts}")
        report.append(f"- **Average alerts per repository**: {total_alerts/total_repos:.1f}")
        report.append("")
        
        # Add age analysis
        now = pd.Timestamp.now().tz_localize(None)
        outstanding = outstanding.copy()  # Make a copy to avoid SettingWithCopyWarning
        outstanding['days_open'] = (now - outstanding['Created At']).dt.days
        
        # Process each repository
        repo_summaries = []
        for repo_name, repo_alerts in repos:
            # Ensure this repo's alerts have the days_open data
            repo_alerts = repo_alerts.copy()
            if 'days_open' not in repo_alerts.columns:
                # Calculate days_open for this subset
                repo_alerts['days_open'] = (now - repo_alerts['Created At']).dt.days
            
            repo_alerts = repo_alerts.sort_values(['Severity', 'days_open'], 
                                                 key=lambda x: x.map({'critical': 5, 'high': 4, 'moderate': 3, 'medium': 3, 'low': 1}) if x.name == 'Severity' else x,
                                                 ascending=[False, False])
            
            severity_counts = repo_alerts['Severity'].value_counts()
            oldest_alert_days = repo_alerts['days_open'].max()
            
            repo_summaries.append({
                'name': repo_name,
                'total_alerts': len(repo_alerts),
                'severity_counts': severity_counts,
                'oldest_days': oldest_alert_days,
                'alerts': repo_alerts
            })
        
        # Sort repositories alphabetically
        repo_summaries.sort(key=lambda x: x['name'])
        
        # Generate repository-by-repository report
        for repo_info in repo_summaries:
            repo_name = repo_info['name']
            repo_alerts = repo_info['alerts']
            severity_counts = repo_info['severity_counts']
            
            report.append(f"## {repo_name}")
            report.append(f"**Total Alerts**: {len(repo_alerts)} | **Oldest Alert**: {repo_info['oldest_days']} days")
            report.append("")
            
            # Severity breakdown
            severity_summary = []
            for severity in ['critical', 'high', 'moderate', 'medium', 'low']:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    severity_summary.append(f"{severity.title()}: {count}")
            
            if severity_summary:
                report.append(f"**Severity Breakdown**: {' | '.join(severity_summary)}")
                report.append("")
            
            # Scope breakdown for dependabot alerts
            dependabot_alerts = repo_alerts[repo_alerts['Tool'] == 'dependabot']
            if len(dependabot_alerts) > 0:
                scope_counts = dependabot_alerts['Dependency Scope'].value_counts()
                scope_summary = []
                
                # Check all possible scopes and be explicit about zeros
                all_scopes = ['RUNTIME', 'DEVELOPMENT', 'UNKNOWN']
                for scope in all_scopes:
                    count = scope_counts.get(scope, 0)
                    if count > 0:
                        scope_summary.append(f"{scope}: {count}")
                    else:
                        scope_summary.append(f"{scope}: 0")
                
                if scope_summary:
                    report.append(f"**Dependency Scope Breakdown**: {' | '.join(scope_summary)}")
                    report.append("")
            
            # Tool breakdown
            tool_counts = repo_alerts['Tool'].value_counts()
            tool_summary = [f"{tool}: {count}" for tool, count in tool_counts.items()]
            report.append(f"**Tools**: {' | '.join(tool_summary)}")
            report.append("")
            
            # List all alerts for this repository
            for idx, (_, alert) in enumerate(repo_alerts.iterrows(), 1):
                report.append(f"### Alert #{alert['Alert Number']} - {alert['Severity'].upper()}")
                report.append(f"- **Tool**: {alert['Tool']}")
                report.append(f"- **Age**: {alert['days_open']} days (created {alert['Created At'].strftime('%Y-%m-%d')})")
                
                # Tool-specific information
                if alert['Tool'] == 'dependabot':
                    if pd.notna(alert['Package']):
                        report.append(f"- **Package**: {alert['Ecosystem']}/{alert['Package']}")
                    if pd.notna(alert['Dependency Scope']):
                        report.append(f"- **Scope**: {alert['Dependency Scope']}")
                    if pd.notna(alert['GHSA ID']):
                        report.append(f"- **GHSA**: {alert['GHSA ID']}")
                        
                elif alert['Tool'] in ['CodeQL', 'code_scanning']:
                    if pd.notna(alert['CodeQL Rule']):
                        report.append(f"- **Rule**: {alert['CodeQL Rule']}")
                
                elif alert['Tool'] == 'secret_scanning':
                    if pd.notna(alert['Secret Type']):
                        report.append(f"- **Secret Type**: {alert['Secret Type']}")
                    if pd.notna(alert['Secret Provider']):
                        report.append(f"- **Provider**: {alert['Secret Provider']}")
                
                # Add enriched data if available
                if include_enriched and self.github_token:
                    enriched = self.get_enriched_alert_summary(alert)
                    if enriched:
                        if alert['Tool'] == 'dependabot':
                            if enriched.get('cve_id') != 'N/A':
                                report.append(f"- **CVE**: {enriched['cve_id']}")
                            if enriched.get('summary') != 'N/A':
                                report.append(f"- **Summary**: {enriched['summary']}")
                            if enriched.get('manifest_path') != 'N/A':
                                report.append(f"- **Manifest**: {enriched['manifest_path']}")
                        
                        elif alert['Tool'] in ['code_scanning', 'CodeQL']:
                            if enriched.get('rule_name') != 'N/A':
                                report.append(f"- **Rule Name**: {enriched['rule_name']}")
                            if enriched.get('location') != 'N/A':
                                report.append(f"- **Location**: {enriched['location']}")
                            if enriched.get('message') != 'N/A':
                                report.append(f"- **Message**: {enriched['message']}")
                
                # Add vulnerability explanation
                explanation = self._get_vulnerability_explanation(alert)
                if explanation:
                    report.append(f"- **Explanation**: {explanation}")
                
                report.append("")
            
            # Repository-specific recommendations
            report.append("### Recommendations for this Repository")
            
            critical_high = len(repo_alerts[repo_alerts['Severity'].isin(['critical', 'high'])])
            if critical_high > 0:
                report.append(f"1. **Urgent**: Address {critical_high} critical/high severity alerts")
            
            aged_alerts = len(repo_alerts[repo_alerts['days_open'] > 90])
            if aged_alerts > 0:
                report.append(f"2. **Review**: {aged_alerts} alerts older than 90 days need triage")
            
            dependabot_alerts = repo_alerts[repo_alerts['Tool'] == 'dependabot']
            if len(dependabot_alerts) > 0:
                top_packages = dependabot_alerts['Package'].value_counts().head(3)
                if len(top_packages) > 0:
                    report.append("3. **Package Updates**:")
                    for package, count in top_packages.items():
                        report.append(f"   - Update {package} ({count} alerts)")
            
            codeql_alerts = repo_alerts[repo_alerts['Tool'] == 'CodeQL']
            if len(codeql_alerts) > 0:
                report.append(f"4. **Code Review**: {len(codeql_alerts)} code quality/security issues to review")
            
            report.append("")
            report.append("---")
            report.append("")
        
        # Overall recommendations
        report.append("## Overall Recommendations Across All Repositories")
        report.append("")
        report.append("### Priority Actions")
        
        # Find common patterns across repositories
        all_packages = outstanding[outstanding['Tool'] == 'dependabot']['Package'].value_counts()
        if len(all_packages) > 0:
            report.append("**Most Common Vulnerable Packages (organization-wide):**")
            for package, count in all_packages.head(10).items():
                affected_repos = len(outstanding[(outstanding['Tool'] == 'dependabot') & 
                                               (outstanding['Package'] == package)]['Repository'].unique())
                report.append(f"- {package}: {count} alerts across {affected_repos} repositories")
            report.append("")
        
        # Repository prioritization
        critical_repos = [r for r in repo_summaries if 
                         r['severity_counts'].get('critical', 0) + r['severity_counts'].get('high', 0) > 0]
        
        if critical_repos:
            report.append("**Repositories requiring immediate attention:**")
            for repo in critical_repos[:10]:
                critical_count = repo['severity_counts'].get('critical', 0) + repo['severity_counts'].get('high', 0)
                report.append(f"- {repo['name']}: {critical_count} critical/high alerts")
            report.append("")
        
        report.append("### Process Improvements")
        report.append("1. **Automated Dependency Updates**: Implement Dependabot auto-merge for low-risk updates")
        report.append("2. **Alert Triage**: Weekly review of alerts older than 30 days")
        report.append("3. **Security Champions**: Assign security champions per repository")
        report.append("4. **CI/CD Integration**: Block deployments with critical/high severity alerts")
        
        # Write report
        with open(output_file, 'w') as f:
            f.write('\n'.join(report))
        
        print(f"Detailed repository report generated: {output_file}")
        return '\n'.join(report)
    
    def export_enriched_csv(self, output_file='enriched_security_alerts.csv'):
        """Export outstanding issues with enriched data"""
        outstanding = self.filter_outstanding_issues().copy()
        
        # Add calculated fields
        # Ensure Created At is datetime type and calculate days open
        try:
            outstanding['Created At'] = pd.to_datetime(outstanding['Created At'], errors='coerce', utc=True).dt.tz_localize(None)
            now_dt = pd.Timestamp.now().tz_localize(None)
            outstanding['Days_Open'] = (now_dt - outstanding['Created At']).dt.days
        except Exception as e:
            print(f"Warning: Could not calculate days open: {e}")
            outstanding['Days_Open'] = 0
        outstanding['Risk_Score'] = outstanding.apply(self._calculate_risk_score, axis=1)
        outstanding['Priority'] = outstanding.apply(self._assign_priority, axis=1)
        
        # Add enriched data columns
        if self.github_token and self.enriched_data:
            enriched_columns = {
                'CVE_ID': [],
                'Advisory_Summary': [],
                'Package_Details': [],
                'Location': [],
                'Rule_Name': []
            }
            
            for _, alert in outstanding.iterrows():
                enriched = self.get_enriched_alert_summary(alert)
                if enriched:
                    enriched_columns['CVE_ID'].append(enriched.get('cve_id', 'N/A'))
                    enriched_columns['Advisory_Summary'].append(enriched.get('summary', 'N/A'))
                    enriched_columns['Package_Details'].append(f"{enriched.get('package_ecosystem', 'N/A')}/{enriched.get('package_name', 'N/A')}")
                    enriched_columns['Location'].append(enriched.get('location', 'N/A'))
                    enriched_columns['Rule_Name'].append(enriched.get('rule_name', 'N/A'))
                else:
                    for col in enriched_columns:
                        enriched_columns[col].append('N/A')
            
            # Add enriched columns to dataframe
            for col, values in enriched_columns.items():
                outstanding[col] = values
        
        # Select and reorder columns
        base_cols = ['Repository', 'Alert Number', 'Tool', 'Severity', 'Days_Open', 'Priority', 'Risk_Score']
        enriched_cols = ['CVE_ID', 'Advisory_Summary', 'Package_Details', 'Location', 'Rule_Name'] if self.github_token and self.enriched_data else []
        remaining_cols = [col for col in outstanding.columns if col not in base_cols + enriched_cols]
        
        export_cols = base_cols + enriched_cols + remaining_cols
        export_cols = [col for col in export_cols if col in outstanding.columns]
        
        outstanding[export_cols].to_csv(output_file, index=False)
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
  
  # API enrichment with token
  python enhanced_security_reporter.py alerts.csv --token YOUR_TOKEN --max-enrich 50
  
  # Custom output directory and multiple report types
  python enhanced_security_reporter.py alerts.csv --assess-all --detailed-repo-report --output-dir ./security_reports
  
  # Include CloudGuard findings with GitHub alerts
  python enhanced_security_reporter.py alerts.csv --detailed-repo-report --cloudguard-csv cloudguard_findings.csv --cloudguard-environments prod nonprod
  
  # CloudGuard reports organized by alert type
  python enhanced_security_reporter.py alerts.csv --cloudguard-csv cloudguard_findings.csv --cloudguard-group-by alert
        """
    )
    
    parser.add_argument('csv_file', help='Path to GitHub security alerts CSV file')
    
    # Authentication and API options
    parser.add_argument('--token', help='GitHub personal access token (or set GITHUB_TOKEN env var)')
    parser.add_argument('--max-enrich', type=int, help='Maximum number of alerts to enrich with API data (for testing)')
    parser.add_argument('--skip-enrichment', action='store_true', help='Skip API enrichment and use CSV data only')
    
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
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.assess_all and args.min_severity != 'high':
        print("Warning: --assess-all overrides --min-severity setting")
    
    # Get GitHub token
    github_token = args.token or os.getenv('GITHUB_TOKEN')
    
    if not github_token and not args.skip_enrichment:
        print("Warning: No GitHub token provided. Use --token or set GITHUB_TOKEN environment variable.")
        print("Reports will be generated using CSV data only. Use --skip-enrichment to suppress this warning.")
    
    # Initialize reporter
    reporter = EnhancedGitHubSecurityReporter(args.csv_file, github_token)
    
    # Apply filters if specified
    if args.repository_filter:
        import re
        pattern = re.compile(args.repository_filter, re.IGNORECASE)
        original_count = len(reporter.df)
        reporter.df = reporter.df[reporter.df['Repository'].str.contains(pattern, na=False)]
        print(f"Repository filter applied: {len(reporter.df)} alerts remaining (was {original_count})")
    
    if args.max_age_days:
        original_count = len(reporter.df)
        cutoff_date = pd.Timestamp.now().tz_localize(None) - pd.Timedelta(days=args.max_age_days)
        reporter.df = reporter.df[reporter.df['Created At'] < cutoff_date]
        print(f"Age filter applied: {len(reporter.df)} alerts remaining (was {original_count})")
    
    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)
    
    # Enrich data if requested and token available
    if not args.skip_enrichment and github_token:
        reporter.enrich_outstanding_alerts(max_alerts=args.max_enrich)
    
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
        summary_only=args.summary_only
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
            include_enriched=not args.skip_enrichment
        )
        print(f"  - {detailed_report_file}")
    
    # Generate CloudGuard reports if requested and available
    if CLOUDGUARD_AVAILABLE and hasattr(args, 'cloudguard_csv') and args.cloudguard_csv:
        if not Path(args.cloudguard_csv).exists():
            print(f"Warning: CloudGuard CSV file {args.cloudguard_csv} not found, skipping CloudGuard reports")
        else:
            print(f"\nGenerating CloudGuard reports from {args.cloudguard_csv}...")
            try:
                cg_reporter = CloudGuardReporter(args.cloudguard_csv)
                
                for environment in args.cloudguard_environments:
                    cg_report_file = output_dir / f'{args.output_prefix}_cloudguard_{environment}_{args.cloudguard_group_by}.md'
                    
                    cg_reporter.generate_environment_report(
                        environment=environment,
                        group_by=args.cloudguard_group_by,
                        output_file=str(cg_report_file)
                    )
                    print(f"  - {cg_report_file}")
                    
            except Exception as e:
                print(f"Error generating CloudGuard reports: {e}")


if __name__ == "__main__":
    main()
