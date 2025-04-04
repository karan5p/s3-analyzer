# S3 Bucket Security Analyzer

A command-line tool that identifies security misconfigurations in AWS S3 buckets and generates detailed reports.

![AWS S3 Security](https://img.shields.io/badge/AWS-S3%20Security-orange)
![Python](https://img.shields.io/badge/Python-3.6%2B-blue)

## 💡 Overview

This project analyzes S3 buckets for common security vulnerabilities:
- Public access settings
- Insecure bucket policies
- Missing encryption
- Disabled versioning
- Logging configuration

Results are provided in easy-to-read reports and stored in a lightweight SQLite database for historical tracking.

## ✨ Features

- **Automated Security Checks** - Scans multiple security aspects of S3 buckets
- **Risk Scoring** - Assigns severity scores to prioritize remediation efforts
- **Simple Setup** - No external database required (uses SQLite)
- **Detailed Reporting** - Generates both technical (JSON) and human-readable reports

## 📋 Requirements

- Python 3.6+
- AWS credentials with S3 read permissions

## 🚀 Quick Start

1. **Clone the repository**
   ```
   git clone https://github.com/yourusername/s3-analyzer.git
   cd s3-analyzer
   ```

2. **Install dependencies**
   ```
   pip install -r requirements.txt
   ```

3. **Run the analyzer**
   ```
   python main.py
   ```

4. **View reports**
   - Check the `reports` directory for generated reports
   - SQLite database is created as `s3_analyzer.db` in the project directory

## ⚙️ Configuration

The `config.yaml` file allows you to customize:

```yaml
# Risk weights determine severity scoring
risk_weights:
  public_access_enabled: 100
  acl_public_read: 80
  policy_public_read: 90
  encryption_disabled: 40
  versioning_disabled: 20
  logging_disabled: 15

# SQLite database settings
sqlite:
  db_file: "s3_analyzer.db"
```

## 📁 Project Structure

```
s3-analyzer/
├── main.py           # Entry point and workflow orchestration
├── analyzer.py       # Security analysis logic
├── reporter.py       # Report generation
├── db_handler.py     # Database operations
├── config.yaml       # Configuration settings
└── requirements.txt  # Project dependencies
```

## 📈 Sample Output

The tool generates both JSON and text reports:

```
================================================================================
S3 BUCKET SECURITY ANALYSIS REPORT - 2025-04-02 22:56:10
================================================================================

SUMMARY:
- Total buckets analyzed: 5
- Buckets with security issues: 5
- Total issues identified: 12

HIGH RISK BUCKETS (Risk Score >= 50):
- my-bpa-disabled-bucket-unique789 (Risk Score: 135)
- my-public-acl-bucket-unique456 (Risk Score: 135)

DETAILED FINDINGS:
--------------------------------------------------------------------------------
Bucket: my-bpa-disabled-bucket-unique789
Region: None
Creation Date: 2025-04-03 01:58:14+00:00
Risk Score: 135

Issues (3):
  1. Block Public Access is not fully enabled (Severity: 100)
  2. Bucket versioning is not enabled (Severity: 20)
  3. Bucket logging is not enabled (Severity: 15)

--------------------------------------------------------------------------------
Bucket: my-encryption-test-bucket-unique345
Region: None
Creation Date: 2025-04-03 01:58:36+00:00
Risk Score: 35

Issues (2):
  1. Bucket versioning is not enabled (Severity: 20)
  2. Bucket logging is not enabled (Severity: 15)

--------------------------------------------------------------------------------
Bucket: my-no-version-log-bucket-unique012
Region: None
Creation Date: 2025-04-03 01:58:30+00:00
Risk Score: 35

Issues (2):
  1. Bucket versioning is not enabled (Severity: 20)
  2. Bucket logging is not enabled (Severity: 15)

--------------------------------------------------------------------------------
Bucket: my-public-acl-bucket-unique456
Region: None
Creation Date: 2025-04-03 01:57:30+00:00
Risk Score: 135

Issues (3):
  1. Block Public Access is not fully enabled (Severity: 100)
  2. Bucket versioning is not enabled (Severity: 20)
  3. Bucket logging is not enabled (Severity: 15)

--------------------------------------------------------------------------------
Bucket: my-secure-test-bucket-unique123
Region: None
Creation Date: 2025-04-03 01:55:26+00:00
Risk Score: 35

Issues (2):
  1. Bucket versioning is not enabled (Severity: 20)
  2. Bucket logging is not enabled (Severity: 15)

================================================================================
END OF REPORT
================================================================================
...
```

## 🔮 Future Enhancements

- Object-level permission analysis
- Sensitive data pattern detection
- Basic web interface with Flask
- Command-line arguments for customized scans
- CSV export options