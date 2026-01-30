# PCI-DSS Cardholder Data Detector

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

A Python tool for detecting credit card numbers in datasets using the Luhn algorithm. Useful for PCI-DSS compliance assessments, scope validation, and cardholder data discovery.

Built by a former Qualified Security Assessor (QSA) to solve real-world compliance challenges.

**📖 [Read the full story](https://cybersecpro.me/posts/finding-hidden-cardholder-data/)** | **📚 [Complete Documentation](https://cybersecpro.me/projects/card-detector/)**

---

## ✨ Features

- ✅ **Luhn Algorithm Validation** - Industry-standard card number verification
- ✅ **Modern BIN Support** - Works with 6-8 digit Bank Identification Numbers
- ✅ **Multiple File Formats** - CSV, TXT, LOG, JSON, XML, SQL files
- ✅ **Directory Scanning** - Recursive search through folder structures
- ✅ **Card Brand Detection** - Visa, Mastercard, Amex, Discover, JCB, Diners
- ✅ **Secure Output** - Masked numbers (BIN + last 4 only)
- ✅ **Compliance Reports** - CSV export for audit documentation
- ✅ **Zero Dependencies** - Uses Python standard library only
- ✅ **CLI & Module** - Use standalone or integrate into your tools

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/juancarlosmunera/pci-card_detector.git
cd pci-card_detector

# Run tests (optional but recommended)
python test_card_detector.py
```

### Basic Usage

```bash
# Scan a CSV file
python card_detector.py --csv transactions.csv

# Scan a log file
python card_detector.py --file application.log

# Scan entire directory with report
python card_detector.py --directory /data --output findings.csv
```

### Python Module Usage

```python
from card_detector import CreditCardDetector

detector = CreditCardDetector()

# Validate a card number
is_valid = detector.luhn_check("4532148803436467")  # Returns True

# Identify card brand
brand = detector.identify_card_brand("4532148803436467")  # Returns "Visa"

# Search text for card numbers
text = "Payment: 4532-1488-0343-6467"
findings = detector.find_card_numbers(text)
print(findings[0]['masked_number'])  # 453214...6467

# Scan files programmatically
findings = detector.scan_csv("data.csv")
detector.generate_report(findings, "report.csv")
```

---

## 📋 Requirements

- Python 3.7 or higher
- No external dependencies (standard library only)

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
```

#### 5. Third-Party Data Validation
Verify vendor data doesn't contain unexpected CHD:
```bash
python card_detector.py --directory /vendor_data --output vendor_scan.csv
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

## 🔍 How It Works

### The Luhn Algorithm

The tool uses the [Luhn algorithm](https://en.wikipedia.org/wiki/Luhn_algorithm) (mod-10 checksum) to validate credit card numbers:

1. Starting from the right, double every second digit
2. If doubling results in a number > 9, subtract 9
3. Sum all digits
4. If sum % 10 == 0, the number is valid

**Example: Validating 4532148803436467**

```
Digits:    4  5  3  2  1  4  8  8  0  3  4  3  6  4  6  7
Double:    ×2    ×2    ×2    ×2    ×2    ×2    ×2    ×2
Result:    8  5  6  2  2  4  7  8  0  3  8  3  3  4  3  7
Sum:       70
Check:     70 % 10 = 0 ✓ VALID
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
⚠ WARNING: 2 potential credit card number(s) detected!

================================================================================

Finding #1:
  File: transactions.csv
  Location: Row 5, Column 3
  Masked Number: 453214...6467
  Card Brand: Visa
  Format: 4532-1488-0343-6467
  Length: 16 digits

Finding #2:
  File: backup.log
  Location: Line 1247
  Masked Number: 542523...9903
  Card Brand: Mastercard
  Format: 5425233430109903
  Length: 16 digits

================================================================================
```

### CSV Report

```csv
file,row,column,line,masked_number,card_brand,original_format,length
transactions.csv,5,3,,453214...6467,Visa,4532-1488-0343-6467,16
backup.log,,,1247,542523...9903,Mastercard,5425233430109903,16
```

---

## 🔐 Security & Privacy

### What This Tool Does ✅

- Scans files locally (no data transmission)
- Masks all numbers in output (first 6 + last 4 only)
- Read-only operation (never modifies files)
- Generates compliance documentation

### What This Tool Does NOT Do ❌

- Store or transmit card numbers
- Test against live payment systems
- Guarantee 100% detection (encrypted data won't be found)
- Replace proper PCI-DSS assessment by a QSA

### Best Practices

1. **Run on isolated systems** - Use copies of data when possible
2. **Secure the output** - Reports contain masked data but should be protected
3. **Delete reports after use** - Don't retain longer than necessary
4. **Use read-only access** - Run with minimal required permissions
5. **Log your scans** - Maintain audit trail for compliance

---

## 🛠️ Advanced Usage

### Custom File Extensions

```bash
python card_detector.py --directory /data --extensions .csv,.log,.txt
```

### Custom Delimiter

```bash
python card_detector.py --csv data.tsv --delimiter $'\t'
```

### Integration with Other Tools

```python
from card_detector import CreditCardDetector

# Use with pandas
import pandas as pd
df = pd.read_csv("data.csv")
detector = CreditCardDetector()

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
