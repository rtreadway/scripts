import json
import time
import requests
import pandas as pd

def fetch_alert_details(alert, github_token):
    """
    Fetch detailed information for a specific alert using GitHub API
    """
    if not github_token:
        return None
    
    headers = {
        'Authorization': f'token {github_token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    
    repo_name = alert['Repository']
    alert_number = alert['Alert Number']
    tool = alert['Tool']
    
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
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            print(f"Alert {alert_number} not found in {repo_name}")
        elif response.status_code == 403:
            print(f"Access denied for {repo_name} - check permissions")
        else:
            print(f"API error {response.status_code} for {repo_name}/{alert_number}")
    except Exception as e:
        print(f"Error fetching alert details for {repo_name}/{alert_number}: {e}")
    
    return None

def enrich_alerts_with_api_data(csv_file, github_token):
    """
    Fetch detailed information for each alert using GitHub API
    """
    df = pd.read_csv(csv_file)
    outstanding = df[df['Resolved At'].isna()]
    
    enriched_data = []
    
    for _, alert in outstanding.iterrows():
        # Rate limiting
        time.sleep(0.1)
        
        details = fetch_alert_details(alert, github_token)
        if details:
            enriched_data.append({
                'repository': alert['Repository'],
                'alert_number': alert['Alert Number'],
                'tool': alert['Tool'],
                'detailed_info': details
            })
    
    return enriched_data

def create_enriched_report(csv_file, github_token=None, max_alerts=10):
    """
    Create a quick enriched report using the functions above
    
    Args:
        csv_file (str): Path to security alerts CSV
        github_token (str): GitHub token for API access
        max_alerts (int): Max alerts to enrich (for testing)
    
    Returns:
        dict: Report data with enriched information
    """
    # Get enriched data
    enriched_data = enrich_alerts_with_api_data(csv_file, github_token)
    
    # Generate SBOM
    df = pd.read_csv(csv_file)
    sbom = generate_sbom_from_alerts(df)
    
    # Create summary report
    outstanding = df[df['Resolved At'].isna()]
    
    report = {
        'summary': {
            'total_outstanding': len(outstanding),
            'enriched_alerts': len(enriched_data),
            'by_severity': outstanding['Severity'].value_counts().to_dict(),
            'by_tool': outstanding['Tool'].value_counts().to_dict()
        },
        'enriched_alerts': enriched_data[:max_alerts],  # Limit for display
        'sbom': sbom,
        'generated_at': pd.Timestamp.now().isoformat()
    }
    
    return report

def generate_sbom_from_alerts(df):
    """Generate SBOM focusing on vulnerable packages"""
    dependabot_alerts = df[df['Tool'] == 'dependabot']
    
    sbom = {
        'packages': [],
        'vulnerabilities': []
    }
    
    for _, alert in dependabot_alerts.iterrows():
        if pd.notna(alert['Package']):
            sbom['packages'].append({
                'name': alert['Package'],
                'ecosystem': alert['Ecosystem'],
                'scope': alert['Dependency Scope'],
                'vulnerabilities': [alert['GHSA ID']]
            })
    
    return sbom