#!/usr/bin/env python3
"""
CloudGuard Security Findings Reporter
Generates comprehensive reports from CloudGuard CSV exports.
"""

import pandas as pd
import argparse
from datetime import datetime
from pathlib import Path


class CloudGuardReporter:
    def __init__(self, csv_file):
        """Initialize the CloudGuard reporter with CSV data."""
        self.csv_file = csv_file
        self.df = None
        self.load_data()
    
    def load_data(self):
        """Load and clean the CloudGuard CSV data."""
        try:
            # Read CSV, handling potential encoding issues
            self.df = pd.read_csv(self.csv_file, encoding='utf-8')
            
            # Clean column names
            self.df.columns = self.df.columns.str.strip()
            
            # Remove empty rows (sometimes CSV exports have empty rows at the end)
            self.df = self.df.dropna(subset=['Title', 'Entity Name'], how='all')
            
            # Parse Created Time with explicit format to avoid warnings
            if 'Created Time' in self.df.columns:
                # CloudGuard uses format like "Jun 29 2025 7:10 PM"
                self.df['Created Time'] = pd.to_datetime(self.df['Created Time'], 
                                                       format='%b %d %Y %I:%M %p', 
                                                       errors='coerce')
            
            # Standardize severity values
            if 'Severity' in self.df.columns:
                self.df['Severity'] = self.df['Severity'].str.lower().str.strip()
            
            # Determine environment from Cloud Account Name
            self.df['Environment'] = self.df['Cloud Account Name'].apply(self._determine_environment)
            
            print(f"Loaded {len(self.df)} CloudGuard findings from {self.csv_file}")
            
        except Exception as e:
            print(f"Error loading CloudGuard CSV: {e}")
            raise
    
    def _determine_environment(self, account_name):
        """Determine environment (prod/nonprod) from cloud account name."""
        if pd.isna(account_name):
            return 'unknown'
        
        account_name_lower = account_name.lower()
        if 'prod' in account_name_lower and 'nonprod' not in account_name_lower:
            return 'prod'
        elif 'nonprod' in account_name_lower or 'test' in account_name_lower or 'dev' in account_name_lower:
            return 'nonprod'
        else:
            return 'unknown'
    
    def get_relevant_columns(self):
        """Get only the relevant columns, ignoring useless fields."""
        ignore_fields = {
            'Organizational Unit Path', 'Cloud Account ID', 'Source', 
            'Acknowledged', 'Comments', 'Labels', 'Is Excluded'
        }
        
        available_columns = set(self.df.columns)
        relevant_columns = available_columns - ignore_fields
        
        # Add computed columns
        relevant_columns.add('Environment')
        
        return sorted(list(relevant_columns))
    
    def generate_environment_report(self, environment, group_by='asset', output_file=None):
        """
        Generate a report for a specific environment.
        
        Args:
            environment: 'prod', 'nonprod', or 'all'
            group_by: 'asset' or 'alert' - how to organize the report
            output_file: Optional output file path
        """
        # Filter by environment
        if environment == 'all':
            env_data = self.df.copy()
            env_title = "All Environments"
        else:
            env_data = self.df[self.df['Environment'] == environment].copy()
            env_title = f"{environment.title()} Environment"
        
        if len(env_data) == 0:
            return f"No findings found for {environment} environment."
        
        # Sort by severity (critical first)
        severity_order = {'critical': 5, 'high': 4, 'medium': 3, 'moderate': 3, 'low': 2, 'info': 1}
        env_data['severity_rank'] = env_data['Severity'].map(severity_order).fillna(0)
        env_data = env_data.sort_values(['severity_rank', 'Created Time'], ascending=[False, False])
        
        report = []
        report.append(f"# CloudGuard Security Findings - {env_title}")
        report.append(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        report.append(f"Data source: {self.csv_file}\n")
        report.append(f"Report Organized By: {group_by}")
        report.append("")
        
        # Executive Summary
        report.append("## Executive Summary")
        total_findings = len(env_data)
        report.append(f"- **Total Findings**: {total_findings}")
        
        # Severity breakdown
        severity_counts = env_data['Severity'].value_counts()
        for severity in ['critical', 'high', 'medium', 'moderate', 'low', 'info']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                report.append(f"- **{severity.title()}**: {count}")
        
        # Environment breakdown (if showing all)
        if environment == 'all':
            env_counts = env_data['Environment'].value_counts()
            report.append("")
            report.append("### By Environment:")
            for env, count in env_counts.items():
                report.append(f"- **{env.title()}**: {count}")
        
        # Account breakdown
        account_counts = env_data['Cloud Account Name'].value_counts()
        report.append("")
        report.append("### Accounts:")
        for account, count in account_counts.head(10).items():
            report.append(f"- **{account}**: {count}")
        
        report.append("")
        
        if group_by == 'asset':
            self._generate_by_asset_section(env_data, report)
        else:
            self._generate_by_alert_section(env_data, report)
        
        # Overall recommendations
        report.append("## Recommendations")
        report.append("### Immediate Actions")
        critical_count = severity_counts.get('critical', 0)
        high_count = severity_counts.get('high', 0)
        
        if critical_count > 0:
            report.append(f"1. **Address {critical_count} Critical findings immediately**")
        if high_count > 0:
            report.append(f"2. **Prioritize {high_count} High severity findings**")
        
        # Top compliance sections
        if 'Compliance Section' in env_data.columns:
            compliance_counts = env_data['Compliance Section'].value_counts().head(5)
            if len(compliance_counts) > 0:
                report.append("")
                report.append("### Focus Areas (Top Compliance Sections):")
                for section, count in compliance_counts.items():
                    if pd.notna(section) and section.strip():
                        report.append(f"- **{section}**: {count} findings")
        
        report_text = '\n'.join(report)
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report_text)
            print(f"CloudGuard report written to: {output_file}")
        
        return report_text
    
    def _generate_by_asset_section(self, env_data, report):
        """Generate report organized by asset (Entity Name)."""
        report.append("## Findings by Asset")
        report.append("*Organized by affected resources*")
        report.append("")
        
        # Group by entity
        asset_groups = env_data.groupby('Entity Name')
        
        for asset_name, asset_findings in asset_groups:
            # Sort findings by severity within each asset
            asset_findings = asset_findings.sort_values('severity_rank', ascending=False)
            
            report.append(f"### {asset_name}")
            report.append("")
            report.append(f"- **Entity Type**: {asset_findings.iloc[0]['Entity Type']}")
            report.append(f"- **Cloud Account**: {asset_findings.iloc[0]['Cloud Account Name']}")
            report.append(f"- **Region**: {asset_findings.iloc[0]['Region']}")
            report.append(f"- **Total Findings**: {len(asset_findings)}")
            
            # Severity breakdown for this asset
            asset_severity = asset_findings['Severity'].value_counts()
            severity_summary = []
            for sev in ['critical', 'high', 'medium', 'moderate', 'low']:
                count = asset_severity.get(sev, 0)
                if count > 0:
                    severity_summary.append(f"{sev.title()}: {count}")
            
            if severity_summary:
                report.append(f"- **Severity Breakdown**: {' | '.join(severity_summary)}")
            
            # Add extra blank line for better visual separation
            report.append("")
            
            # List findings for this asset
            for idx, (_, finding) in enumerate(asset_findings.iterrows(), 1):
                report.append(f"#### Finding #{idx} - {finding['Severity'].upper()}")
                report.append(f"- **Title**: {finding['Title']}")
                if pd.notna(finding.get('Compliance Section')) and finding['Compliance Section'].strip():
                    report.append(f"- **Compliance Section**: {finding['Compliance Section']}")
                if pd.notna(finding.get('Created Time')):
                    report.append(f"- **Created**: {finding['Created Time'].strftime('%Y-%m-%d')}")
                if pd.notna(finding.get('Description')):
                    desc = str(finding['Description']).strip()[:200]
                    if len(str(finding['Description']).strip()) > 200:
                        desc += "..."
                    report.append(f"- **Description**: {desc}")
                
                # Add remediation for each finding if available
                if pd.notna(finding.get('Remediation')):
                    remediation = str(finding['Remediation']).strip()
                    if remediation and len(remediation) > 10:  # Skip empty or very short remediation
                        # Format remediation text better for inline display
                        if '. ' in remediation and any(char.isdigit() for char in remediation[:20]):
                            # If it has numbered steps, show first step only for brevity
                            import re
                            first_step = re.split(r'\d+\.\s', remediation)[1] if len(re.split(r'\d+\.\s', remediation)) > 1 else remediation
                            if len(first_step) > 150:
                                first_step = first_step[:150] + "..."
                            report.append(f"- **Remediation**: {first_step.strip()}")
                        else:
                            # Truncate long remediation text for inline display
                            if len(remediation) > 150:
                                remediation = remediation[:150] + "..."
                            report.append(f"- **Remediation**: {remediation}")
                
                report.append("")
            
            report.append("---")
            report.append("")
    
    def _generate_by_alert_section(self, env_data, report):
        """Generate report organized by alert type (Title)."""
        report.append("## Findings by Alert Type")
        report.append("*Organized by type of security finding*")
        report.append("")
        
        # Group by alert title
        alert_groups = env_data.groupby('Title')
        
        # Sort alert groups by severity and count
        alert_summary = []
        for title, group in alert_groups:
            max_severity_rank = group['severity_rank'].max()
            count = len(group)
            alert_summary.append((title, max_severity_rank, count, group))
        
        # Sort by severity (highest first), then by count
        alert_summary.sort(key=lambda x: (x[1], x[2]), reverse=True)
        
        for title, max_severity_rank, count, alert_findings in alert_summary:
            # Get severity name from rank
            severity_name = alert_findings.iloc[0]['Severity']
            
            report.append(f"### {title}")
            report.append(f"**Severity**: {severity_name.upper()}")
            report.append(f"**Total Affected Assets**: {count}")
            
            # Compliance section if available
            if pd.notna(alert_findings.iloc[0].get('Compliance Section')):
                comp_section = alert_findings.iloc[0]['Compliance Section']
                if comp_section.strip():
                    report.append(f"**Compliance Section**: {comp_section}")
            
            # Description
            if pd.notna(alert_findings.iloc[0].get('Description')):
                desc = str(alert_findings.iloc[0]['Description']).strip()[:300]
                if len(str(alert_findings.iloc[0]['Description']).strip()) > 300:
                    desc += "..."
                report.append(f"**Description**: {desc}")
            
            report.append("")
            report.append("#### Affected Assets:")
            
            # List affected assets
            for _, finding in alert_findings.iterrows():
                report.append(f"- **{finding['Entity Name']}** ({finding['Entity Type']}) - {finding['Cloud Account Name']}")
            
            # Remediation if available
            if pd.notna(alert_findings.iloc[0].get('Remediation')):
                remediation = str(alert_findings.iloc[0]['Remediation']).strip()
                if remediation and len(remediation) > 10:  # Skip empty or very short remediation
                    report.append("")
                    report.append("#### Remediation:")
                    
                    # Format remediation text better
                    # If it contains numbered steps, format them properly
                    if '. ' in remediation and any(char.isdigit() for char in remediation[:20]):
                        # Split on numbered steps and format
                        import re
                        # Split on patterns like "1. ", "2. ", etc.
                        steps = re.split(r'(\d+\.\s)', remediation)
                        formatted_remediation = []
                        current_step = ""
                        
                        for part in steps:
                            if re.match(r'\d+\.\s', part):  # This is a step number
                                if current_step:  # Save previous step
                                    formatted_remediation.append(current_step.strip())
                                current_step = part
                            else:
                                current_step += part
                        
                        if current_step:  # Add the last step
                            formatted_remediation.append(current_step.strip())
                        
                        # Join steps with line breaks
                        if len(formatted_remediation) > 1:
                            remediation = '\n'.join(formatted_remediation)
                    
                    # Truncate very long remediation text
                    if len(remediation) > 1000:
                        remediation = remediation[:1000] + "..."
                    
                    report.append(remediation)
            
            report.append("")
            report.append("---")
            report.append("")


def main():
    """Main CLI interface for CloudGuard reporter."""
    parser = argparse.ArgumentParser(
        description="CloudGuard Security Findings Reporter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate prod environment report by asset
  python cloudguard_reporter.py findings.csv --environment prod --group-by asset
  
  # Generate nonprod environment report by alert type
  python cloudguard_reporter.py findings.csv --environment nonprod --group-by alert
  
  # Generate all environments report
  python cloudguard_reporter.py findings.csv --environment all --output-dir ./reports
        """
    )
    
    parser.add_argument('csv_file', help='Path to CloudGuard findings CSV file')
    parser.add_argument('--environment', choices=['prod', 'nonprod', 'all'], 
                       default='all', help='Environment to report on (default: all)')
    parser.add_argument('--group-by', choices=['asset', 'alert'], 
                       default='asset', help='Group findings by asset or alert type (default: asset)')
    parser.add_argument('--output-dir', default='.', 
                       help='Output directory for reports (default: current directory)')
    parser.add_argument('--output-prefix', default='cloudguard_report',
                       help='Prefix for output files (default: cloudguard_report)')
    
    args = parser.parse_args()
    
    # Validate input file
    if not Path(args.csv_file).exists():
        print(f"Error: CSV file {args.csv_file} not found")
        return 1
    
    try:
        # Initialize reporter
        reporter = CloudGuardReporter(args.csv_file)
        
        # Create output directory
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate report
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = output_dir / f"{args.output_prefix}_{args.environment}_{args.group_by}_{timestamp}.md"
        
        report_content = reporter.generate_environment_report(
            environment=args.environment,
            group_by=args.group_by,
            output_file=output_file
        )
        
        print(f"Report generated successfully: {output_file}")
        
        # Print summary
        lines = report_content.split('\n')
        summary_lines = [line for line in lines[:20] if line.startswith('- **')]
        if summary_lines:
            print("\nSummary:")
            for line in summary_lines:
                print(line)
        
        return 0
        
    except Exception as e:
        print(f"Error generating CloudGuard report: {e}")
        return 1


if __name__ == "__main__":
    exit(main())
