# PCI-DSS Cardholder Data Detector

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

A Python tool for detecting credit card numbers in datasets using the Luhn algorithm. Useful for PCI-DSS compliance assessments, scope validation, and cardholder data discovery across files, databases, and cloud storage.

Built by a former Qualified Security Assessor (QSA) to solve real-world compliance challenges.

**📖 [Read the full story](https://cybersecpro.me/posts/finding-hidden-cardholder-data/)** | **📚 [Complete Documentation](https://cybersecpro.me/projects/card-detector/)**

---

## ✨ Features

- ✅ **Luhn Algorithm Validation** - Industry-standard card number verification
- ✅ **Modern BIN Support** - Works with 6-8 digit Bank Identification Numbers
- ✅ **Multiple File Formats** - CSV, TXT, LOG, JSON, XML, SQL, PDF, Excel
- ✅ **Database Scanning** - SQLite (built-in), PostgreSQL, MySQL
- ✅ **Cloud Storage** - Amazon S3, Google Cloud Storage, Azure Blob Storage
- ✅ **Directory Scanning** - Recursive search through folder structures
- ✅ **Decode Mode** - Detect card numbers hidden behind Base64, Hex, URL, HTML entity, and Unicode encoding
- ✅ **Card Brand Detection** - Visa, Mastercard, Amex, Discover, JCB, Diners
- ✅ **Secure Output** - Masked numbers (BIN + last 4 only)
- ✅ **Compliance Reports** - CSV export for audit documentation
- ✅ **CLI & Module** - Use standalone or integrate into your tools

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/juancarlosmunera/pci-card_detector.git
cd pci-card_detector

# No install required for core file scanning (standard library only).
# For databases, documents, or cloud storage, install only what you need:
pip install -r requirements.txt   # installs everything
# -- or individually --
pip install psycopg2-binary          # PostgreSQL
pip install mysql-connector-python   # MySQL
pip install pdfplumber               # PDF files
pip install openpyxl                 # Excel files
pip install boto3                    # Amazon S3
pip install google-cloud-storage     # Google Cloud Storage
pip install azure-storage-blob       # Azure Blob Storage

# Run tests (optional but recommended)
python test_card_detector.py
```

### Basic Usage

```bash
# Scan a CSV file
python card_detector.py --csv transactions.csv

# Scan a log file
python card_detector.py --file application.log

# Scan a PDF invoice
python card_detector.py --pdf invoice.pdf

# Scan an Excel workbook
python card_detector.py --excel report.xlsx

# Scan entire directory with report
python card_detector.py --directory /data --output findings.csv

# Suspect data may be encoded? Enable decode mode
python card_detector.py --csv transactions.csv --decode-mode
python card_detector.py --directory /data --decode-mode --output findings.csv
```

---

## 📋 Requirements

- **Python 3.7+**
- **Core scanning** (files, SQLite): no external dependencies — standard library only
- **Optional connectors**: install per the table below

| Datasource | Install |
|---|---|
| PostgreSQL | `pip install psycopg2-binary` |
| MySQL | `pip install mysql-connector-python` |
| PDF files | `pip install pdfplumber` |
| Excel files | `pip install openpyxl` |
| Amazon S3 | `pip install boto3` |
| Google Cloud Storage | `pip install google-cloud-storage` |
| Azure Blob Storage | `pip install azure-storage-blob` |

---

## 🎯 Use Cases

### PCI-DSS Compliance

#### 1. Pre-Assessment Discovery
Scan your environment before your annual assessment to find unexpected cardholder data:
```bash
python card_detector.py --directory /production --output pre_assessment.csv
```

#### 2. Scope Validation (Requirement 12.5.2)
Verify card data doesn't exist outside your defined CDE:
```bash
python card_detector.py --directory /out_of_scope --output scope_validation.csv
python card_detector.py --pg-host db.internal --pg-db app --pg-user readonly --pg-password s3cr3t --output db_scope.csv
```

#### 3. Log Analysis (Requirement 10.2)
Ensure logs don't contain inadvertent cardholder data:
```bash
python card_detector.py --directory /var/log --output log_analysis.csv
```

#### 4. Data Retention Validation (Requirement 3.1)
Confirm old data has been properly purged:
```bash
python card_detector.py --csv archived_transactions.csv
python card_detector.py --sqlite /var/db/archive.db
```

#### 5. Third-Party Data Validation
Verify vendor data doesn't contain unexpected CHD:
```bash
python card_detector.py --s3-bucket vendor-uploads --s3-prefix q4-data/ --output vendor_scan.csv
```

### Development & DevOps

```bash
# Prevent card numbers from entering your codebase
python card_detector.py --directory ./src

# Automated compliance checks in CI/CD
if python card_detector.py --csv new_data.csv; then
  echo "✓ No card data detected"
else
  echo "✗ Card data found - pipeline failed"
  exit 1
fi
```

---

## 🗄️ Database Scanning

The tool connects directly to relational databases and scans all text-like columns across all tables. A `--row-limit` (default 10 000) prevents accidental full-table scans on very large databases.

### SQLite

No extra install required — SQLite is part of the Python standard library.

```bash
python card_detector.py --sqlite /var/db/app.db
python card_detector.py --sqlite app.db --row-limit 50000 --output findings.csv
```

### PostgreSQL

```bash
pip install psycopg2-binary

python card_detector.py \
  --pg-host localhost \
  --pg-db mydb \
  --pg-user alice \
  --pg-password s3cr3t \
  --pg-schema public \
  --output findings.csv
```

### MySQL

```bash
pip install mysql-connector-python

python card_detector.py \
  --mysql-host 10.0.0.5 \
  --mysql-db sales \
  --mysql-user root \
  --mysql-password pass \
  --row-limit 5000
```

### Python API — databases

```python
from card_detector import CreditCardDetector

detector = CreditCardDetector()

# SQLite
findings = detector.scan_sqlite("app.db", row_limit=10000)

# PostgreSQL
findings = detector.scan_postgres(
    host="localhost", dbname="mydb",
    user="alice", password="s3cr3t",
    schema="public"
)

# MySQL
findings = detector.scan_mysql(
    host="10.0.0.5", database="sales",
    user="root", password="pass"
)

detector.generate_report(findings, "db_report.csv")
```

---

## ☁️ Cloud Storage Scanning

Cloud scanners list objects in a bucket, download each supported file to a temporary directory, scan it, then delete the local copy automatically.

Supported file types in cloud buckets: `.csv`, `.txt`, `.log`, `.json`, `.xml`, `.sql`, `.pdf`, `.xlsx`

### Amazon S3

Credentials are resolved from the standard AWS chain (environment variables, `~/.aws/credentials`, IAM role). You can also pass keys explicitly.

```bash
pip install boto3

# Uses default AWS credentials
python card_detector.py --s3-bucket my-bucket --output findings.csv

# With prefix filter and explicit region
python card_detector.py --s3-bucket my-bucket --s3-prefix exports/2024/ --s3-region us-east-1

# Credentials via environment variables (recommended over inline flags)
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
python card_detector.py --s3-bucket my-bucket
```

### Google Cloud Storage

Credentials are resolved from Application Default Credentials (`GOOGLE_APPLICATION_CREDENTIALS` env var or `gcloud auth application-default login`).

```bash
pip install google-cloud-storage

python card_detector.py --gcs-bucket my-bucket
python card_detector.py --gcs-bucket my-bucket --gcs-prefix backups/q4/
```

### Azure Blob Storage

Pass the connection string via flag or environment variable.

```bash
pip install azure-storage-blob

# Via flag
python card_detector.py \
  --azure-container backups \
  --azure-conn-string "DefaultEndpointsProtocol=https;AccountName=..."

# Via environment variable (recommended)
export AZURE_STORAGE_CONNECTION_STRING="DefaultEndpointsProtocol=https;AccountName=..."
python card_detector.py --azure-container backups --azure-prefix exports/
```

### Python API — cloud storage

```python
from card_detector import CreditCardDetector

detector = CreditCardDetector()

# Amazon S3
findings = detector.scan_s3("my-bucket", prefix="exports/")

# Google Cloud Storage
findings = detector.scan_gcs("my-bucket", prefix="backups/q4/")

# Azure Blob Storage
findings = detector.scan_azure_blob(
    "backups",
    connection_string="DefaultEndpointsProtocol=https;..."
)

detector.generate_report(findings, "cloud_report.csv")
```

---

## 📄 Document Scanning

### PDF

```bash
pip install pdfplumber

python card_detector.py --pdf invoice.pdf
python card_detector.py --pdf statement.pdf --output findings.csv
```

### Excel

```bash
pip install openpyxl

python card_detector.py --excel report.xlsx
python card_detector.py --excel data.xlsx --output findings.csv
```

Both are also picked up automatically when scanning a directory.

---

## 🔍 How It Works

### The Luhn Algorithm

The tool uses the [Luhn algorithm](https://en.wikipedia.org/wiki/Luhn_algorithm) (mod-10 checksum) to validate credit card numbers:

1. Starting from the right, double every second digit
2. If doubling results in a number > 9, subtract 9
3. Sum all digits
4. If sum % 10 == 0, the number is valid

**Example: Validating 4111111111111111** (standard Visa test card)

```
Digits:    4  1  1  1  1  1  1  1  1  1  1  1  1  1  1  1
Double:    ×2    ×2    ×2    ×2    ×2    ×2    ×2    ×2
Result:    8  1  2  1  2  1  2  1  2  1  2  1  2  1  2  1
Sum:       30
Check:     30 % 10 = 0 ✓ VALID
```

### Modern BIN Support

The Luhn algorithm works regardless of BIN length (6-8 digits) because it validates the entire card number, not individual components. Supports:

- 13-digit cards (some Visa)
- 15-digit cards (American Express)
- 16-digit cards (most brands)
- 19-digit cards (modern extended format)

---

## 📊 Output Examples

### Console Output

```
[WARNING] 3 potential credit card number(s) detected!

================================================================================

Finding #1:
  Source   : transactions.csv
  Location : Row 5, Column 3
  Masked   : 453214...6467
  Brand    : Visa
  Format   : 4532-1488-0343-6467
  Length   : 16 digits

Finding #2:
  Source   : sqlite:app.db
  Location : Table=orders, Column=notes, RowID=1042
  Masked   : 542523...9903
  Brand    : Mastercard
  Format   : 5425233430109903
  Length   : 16 digits

Finding #3:
  Source   : s3://my-bucket/exports/q4.csv
  Location : Row 18, Column 2
  Masked   : 378282...0005
  Brand    : Amex
  Format   : 378282246310005
  Length   : 15 digits

================================================================================
```

### CSV Report

```csv
source,file,table,column,row_id,sheet,row,line,page,masked_number,card_brand,original_format,length,detected_encoding,context,cell_content
,transactions.csv,,,,,5,,,411111...1111,Visa,4111111111111111,16,plain,,4111111...
sqlite:app.db,,orders,notes,1042,,,,,542523...9903,Mastercard,5425233430109903,16,plain,,5425233...
s3://my-bucket/exports/q4.csv,s3://my-bucket/exports/q4.csv,,,,,18,,,378282...0005,Amex,378282246310005,15,plain,,378282...
,application.log,,,,,47,,,411111...1111,Visa,4111111111111111,16,base64,NDExMTEx...,
```

---

## 🐍 Python Module Reference

```python
from card_detector import CreditCardDetector

# Standard mode
detector = CreditCardDetector()

# Encoding-aware mode — tries to decode obfuscated data before scanning
detector = CreditCardDetector(decode_mode=True)

# ── Core validation ───────────────────────────────────────────────────────────
detector.luhn_check("4111111111111111")           # → True
detector.identify_card_brand("4111111111111111")  # → "Visa"
detector.find_card_numbers("Card: 4111-1111-1111-1111")  # → list of findings
# Each finding dict includes 'detected_encoding': 'plain' | 'base64' | 'hex' | 'url' | ...

# ── File scanners ─────────────────────────────────────────────────────────────
detector.scan_csv("data.csv", delimiter=",")
detector.scan_text_file("application.log")
detector.scan_pdf("invoice.pdf")
detector.scan_excel("report.xlsx")
detector.scan_directory("/data/")

# ── Database scanners ─────────────────────────────────────────────────────────
detector.scan_sqlite("app.db", row_limit=10000)
detector.scan_postgres(host, dbname, user, password, port=5432, schema="public")
detector.scan_mysql(host, database, user, password, port=3306)

# ── Cloud storage scanners ────────────────────────────────────────────────────
detector.scan_s3(bucket, prefix="", region=None)
detector.scan_gcs(bucket, prefix="")
detector.scan_azure_blob(container, prefix="", connection_string=None)

# ── Reporting ─────────────────────────────────────────────────────────────────
detector.generate_report(findings, output_path="report.csv")
detector.save_report_csv(findings, "report.csv")
```

---

## 🔐 Security & Privacy

### What This Tool Does ✅

- Scans files and databases locally (no data transmitted to third parties)
- Masks all numbers in output (first 6 + last 4 only)
- Read-only operation (never modifies files or database rows)
- Downloads cloud files to a temporary directory that is deleted automatically
- Generates compliance documentation

### What This Tool Does NOT Do ❌

- Store or transmit card numbers
- Test against live payment systems
- Guarantee 100% detection (encrypted/hashed data won't be found)
- Replace proper PCI-DSS assessment by a QSA

### Best Practices

1. **Avoid inline credentials** - Use environment variables or credential files for database and cloud passwords instead of CLI flags (flags appear in process listings)
2. **Use read-only accounts** - Connect to databases with a read-only user that has SELECT-only access
3. **Run on isolated systems** - Use copies of data when possible
4. **Secure the output** - Reports contain masked data but should still be protected
5. **Delete reports after use** - Don't retain longer than necessary
6. **Log your scans** - Maintain an audit trail for compliance

---

## 🔓 Decode Mode

Some systems store or log card numbers in encoded form — intentionally obfuscated, or simply because a middleware layer applied an encoding before writing the data. Standard scanning misses these entirely.

Enable `--decode-mode` to instruct the tool to attempt decoding each text chunk through five common schemes before scanning it:

| Encoding | Example of hidden card `4111111111111111` |
|---|---|
| URL / percent | `%34%31%31%31%31%31%31%31%31%31%31%31%31%31%31%31` |
| HTML entities | `&#52;&#49;&#49;&#49;&#49;&#49;&#49;&#49;&#49;&#49;&#49;&#49;&#49;&#49;&#49;&#49;` |
| Unicode escapes | `\u0034\u0031\u0031\u0031\u0031\u0031\u0031\u0031\u0031\u0031\u0031\u0031\u0031\u0031\u0031\u0031` |
| Base64 | `NDExMTExMTExMTExMTExMQ==` |
| Hex | `34313131313131313131313131313131` |

Findings discovered after decoding are tagged with the encoding name so you know exactly how the number was hidden.

### CLI usage

```bash
# Add --decode-mode to any scan command
python card_detector.py --csv transactions.csv --decode-mode
python card_detector.py --file application.log --decode-mode --output findings.csv
python card_detector.py --directory /data --decode-mode
python card_detector.py --sqlite app.db --decode-mode
python card_detector.py --s3-bucket my-bucket --decode-mode
```

### Console output with decode mode

```
[WARNING] 2 potential credit card number(s) detected!

================================================================================

Finding #1:
  Source   : transactions.csv
  Location : Row 3, Column 2
  Masked   : 411111...1111
  Brand    : Visa
  Format   : 4111111111111111
  Length   : 16 digits

Finding #2:
  Source   : application.log
  Location : Line 47
  Masked   : 411111...1111
  Brand    : Visa
  Format   : 4111111111111111
  Length   : 16 digits
  Encoding : base64  [found after decoding]

================================================================================
```

The `Encoding` line only appears when the number was found after decoding — plain-text findings are unchanged.

### CSV report with decode mode

The `detected_encoding` column in the CSV report records how each number was found:

```csv
source,file,...,masked_number,card_brand,original_format,length,detected_encoding,...
,transactions.csv,...,411111...1111,Visa,4111111111111111,16,plain,...
,application.log,...,411111...1111,Visa,4111111111111111,16,base64,...
```

### Python API — decode mode

```python
from card_detector import CreditCardDetector

# Enable at construction time — applies to all scan methods
detector = CreditCardDetector(decode_mode=True)

findings = detector.scan_csv("transactions.csv")
findings += detector.scan_text_file("application.log")
findings += detector.scan_sqlite("app.db")

for f in findings:
    if f['detected_encoding'] != 'plain':
        print(f"Encoded card found! Scheme: {f['detected_encoding']}, "
              f"Masked: {f['masked_number']}")

detector.generate_report(findings, "findings.csv")
```

### When to use decode mode

| Scenario | Recommendation |
|---|---|
| Standard compliance scan | Off (default) — faster, fewer false positives |
| Suspicious log files or API responses | On — check for URL/HTML encoding |
| Data from third-party vendors or ETL pipelines | On — Base64 and Hex are common transport encodings |
| Internal application databases | On — some ORMs or serialisers apply Base64 to BLOB columns |
| Very large datasets where performance matters | Off, then re-run with `--decode-mode` only on suspect files |

> **Note:** Decode mode increases scan time and may surface additional false positives (other base64/hex strings that happen to decode into Luhn-valid digit sequences). Review flagged encoded findings carefully.

---

## 🛠️ Advanced Usage

### Custom CSV Delimiter

```bash
python card_detector.py --csv data.tsv --delimiter $'\t'
```

### Limit Database Row Scanning

```bash
# Scan only the first 1 000 rows per table (useful for large databases)
python card_detector.py --sqlite app.db --row-limit 1000
```

### Filter Cloud Storage by Prefix

```bash
python card_detector.py --s3-bucket my-bucket --s3-prefix finance/2024/Q4/
python card_detector.py --gcs-bucket my-bucket --gcs-prefix backups/
python card_detector.py --azure-container data --azure-prefix exports/monthly/
```

### Integration with Other Tools

```python
from card_detector import CreditCardDetector
import pandas as pd

detector = CreditCardDetector()
df = pd.read_csv("data.csv")

for col in df.columns:
    for value in df[col]:
        if detector.luhn_check(str(value)):
            print(f"Found card in {col}: {value}")
```

---

## 🧪 Testing

Run the test suite to verify everything works:

```bash
python test_card_detector.py
```

The test suite includes:
- Luhn algorithm validation tests
- Card brand detection tests
- Text search functionality tests
- Modern BIN length support tests
- Sample file generation

---

## 📖 Documentation

- **Full Documentation:** [cybersecpro.me/projects/card-detector](https://cybersecpro.me/projects/card-detector/)
- **Blog Post:** [Finding Hidden Cardholder Data](https://cybersecpro.me/posts/finding-hidden-cardholder-data/)
- **PCI-DSS Guide:** [Essential Best Practices](https://cybersecpro.me/posts/pci-dss-compliance-best-practices/)

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

### Report Issues
Found a bug? Have a feature request? [Open an issue](https://github.com/juancarlosmunera/pci-card_detector/issues)

### Submit Pull Requests
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Suggest Improvements
Have ideas? [Start a discussion](https://github.com/juancarlosmunera/pci-card_detector/discussions)

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**Juan Carlos Munera**
- Former Qualified Security Assessor (QSA)
- Cybersecurity & Compliance Professional
- Website: [cybersecpro.me](https://cybersecpro.me)
- LinkedIn: [juancarlosmunera](https://linkedin.com/in/juancarlosmunera)

---

## 🙏 Acknowledgments

- Built from real-world PCI-DSS assessment experience
- Inspired by the need for accessible compliance tools
- Thanks to the open source community for feedback and contributions

---

## ⭐ Support

If you find this tool useful:
- ⭐ Star this repository
- 🐛 Report bugs or request features via [issues](https://github.com/juancarlosmunera/pci-card_detector/issues)
- 📢 Share with others who might benefit
- 💼 Connect on [LinkedIn](https://linkedin.com/in/juancarlosmunera)

---

## 📚 Related Resources

- [PCI Security Standards Council](https://www.pcisecuritystandards.org/)
- [PCI DSS v4.0 Requirements](https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0.pdf)
- [Luhn Algorithm on Wikipedia](https://en.wikipedia.org/wiki/Luhn_algorithm)
- [My PCI-DSS Blog Series](https://cybersecpro.me/tags/pci-dss/)

---

## ⚠️ Disclaimer

This tool is provided for compliance and security purposes only. It does not replace professional PCI-DSS assessment by a Qualified Security Assessor. Always follow your organization's security policies and consult with qualified professionals for production deployments.

---

**Made with ❤️ by a former QSA to help organizations achieve better security compliance**
