"""
AWS Security Group Analyzer - Reporter Module
Handles the generation of reports based on security analysis results.
"""

import logging
import json
import os
from datetime import datetime

logger = logging.getLogger(__name__)

def generate_report(analyzed_data, output_dir="reports"):
    """
    Generates a report based on the analysis results.
    
    Args:
        analyzed_data: List of analyzed bucket data with security findings
        output_dir: Directory to save the report files
        
    Returns:
        str: Path to the generated report
    """
    if not analyzed_data:
        logger.warning("No data to generate report")
        return None
        
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate timestamp for report filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_report_path = os.path.join(output_dir, f"s3_security_report_{timestamp}.json")
    txt_report_path = os.path.join(output_dir, f"s3_security_report_{timestamp}.txt")
    
    # Save detailed report as JSON
    try:
        with open(json_report_path, 'w') as f:
            json.dump(analyzed_data, f, indent=2, default=str)
        logger.info(f"Detailed JSON report saved to: {json_report_path}")
    except Exception as e:
        logger.error(f"Error saving JSON report: {e}", exc_info=True)
    
    # Generate and save text report
    try:
        with open(txt_report_path, 'w') as f:
            # Write report header
            f.write("=" * 80 + "\n")
            f.write(f"S3 BUCKET SECURITY ANALYSIS REPORT - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            # Summary statistics
            total_buckets = len(analyzed_data)
            buckets_with_issues = sum(1 for b in analyzed_data if b.get('issues'))
            total_issues = sum(len(b.get('issues', [])) for b in analyzed_data)
            
            f.write(f"SUMMARY:\n")
            f.write(f"- Total buckets analyzed: {total_buckets}\n")
            f.write(f"- Buckets with security issues: {buckets_with_issues}\n")
            f.write(f"- Total issues identified: {total_issues}\n\n")
            
            # High-risk buckets
            high_risk_buckets = [b for b in analyzed_data if b.get('risk_score', 0) >= 50]
            if high_risk_buckets:
                f.write(f"HIGH RISK BUCKETS (Risk Score >= 50):\n")
                for bucket in sorted(high_risk_buckets, key=lambda x: x.get('risk_score', 0), reverse=True):
                    f.write(f"- {bucket['name']} (Risk Score: {bucket['risk_score']})\n")
                f.write("\n")
            
            # Detailed findings for each bucket
            f.write("DETAILED FINDINGS:\n")
            for bucket in analyzed_data:
                f.write("-" * 80 + "\n")
                f.write(f"Bucket: {bucket['name']}\n")
                f.write(f"Region: {bucket.get('region', 'unknown')}\n")
                f.write(f"Creation Date: {bucket.get('creation_date', 'unknown')}\n")
                f.write(f"Risk Score: {bucket.get('risk_score', 0)}\n")
                
                issues = bucket.get('issues', [])
                if issues:
                    f.write(f"\nIssues ({len(issues)}):\n")
                    for i, issue in enumerate(issues, 1):
                        f.write(f"  {i}. {issue['description']} (Severity: {issue['severity']})\n")
                else:
                    f.write("\nNo security issues identified.\n")
                f.write("\n")
            
            # Report footer
            f.write("=" * 80 + "\n")
            f.write("END OF REPORT\n")
            f.write("=" * 80 + "\n")
        
        logger.info(f"Text report saved to: {txt_report_path}")
        return txt_report_path
    except Exception as e:
        logger.error(f"Error generating text report: {e}", exc_info=True)
        return json_report_path  # Return JSON report path as fallback

# HTML report functionality to be implemented in the future