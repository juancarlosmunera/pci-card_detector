# PCI-DSS Cardholder Data Discovery Tool

A Python script for detecting credit card numbers in datasets using the Luhn algorithm (mod-10 checksum). Designed for PCI-DSS compliance, risk management, and data discovery exercises.

**Remember**: This tool helps you find cardholder data. With great power comes great responsibility!

## Features

✓ **Luhn Algorithm Validation** - Accurate credit card number detection<br>
✓ **Modern BIN Support** - Works with 6-8 digit Bank Identification Numbers<br>
✓ **Multiple File Formats** - CSV, TXT, LOG, JSON, XML, SQL<br>
✓ **Directory Scanning** - Recursive search through folder structures<br>
✓ **Card Brand Identification** - Detects Visa, Mastercard, Amex, Discover, etc.<br>
✓ **Masked Output** - Shows only BIN + last 4 digits for security<br>
✓ **CSV Reports** - Export findings for compliance documentation<br>
✓ **CLI and Module** - Use standalone or integrate into your tools<br>

## The Luhn Algorithm and BIN Changes

### Does the Luhn Algorithm Still Work?

**YES!** The Luhn algorithm (mod-10 checksum) is independent of BIN length. Here's why:

### What Changed in BINs?

In 2022, the payments industry began transitioning from 6-digit BINs to 8-digit BINs:
- **Old Format**: 6-digit BIN + account number + check digit = 16 total digits
- **New Format**: 8-digit BIN + account number + check digit = 16-19 total digits

**Important**: The Luhn algorithm validates the ENTIRE card number, not individual components. Whether the BIN is 6, 7, or 8 digits doesn't affect validation.

### How Luhn Works

```python
# Example: Validate 4532148803436467 (valid Visa)

Step 1: Start from the right, double every second digit
4  5  3  2  1  4  8  8  0  3  4  3  6  4  6  7
×2    ×2    ×2    ×2    ×2    ×2    ×2    ×2

8  5  6  2  2  4  16 8  0  3  8  3  12 4  12 7

Step 2: If doubled digit > 9, subtract 9
8  5  6  2  2  4  7  8  0  3  8  3  3  4  3  7

Step 3: Sum all digits
8+5+6+2+2+4+7+8+0+3+8+3+3+4+3+7 = 70

Step 4: Check if sum % 10 == 0
70 % 10 = 0 ✓ VALID
```

The algorithm works on the complete number regardless of internal structure.

## Installation

### Requirements
- Python 3.7+
- No external dependencies (uses standard library only)

### Setup
```bash
# Clone or download the script
git clone https://github.com/pci-dss/card-detector/card-detector.git
cd card-detector

# Make executable (optional)
chmod +x card_detector.py
```

## Usage

### Command Line Interface

#### Scan a Single CSV File
```bash
python card_detector.py --csv transactions.csv
```

#### Scan with Custom Delimiter
```bash
# Tab-delimited
python card_detector.py --csv data.tsv --delimiter $'\t'

# Pipe-delimited
python card_detector.py --csv data.txt --delimiter '|'
```

#### Scan a Text/Log File
```bash
python card_detector.py --file application.log
```

#### Scan Entire Directory
```bash
python card_detector.py --directory /path/to/data
```

#### Generate CSV Report
```bash
python card_detector.py --directory /data --output findings_report.csv
```

### Use as Python Module

```python
from card_detector import CreditCardDetector

# Initialize detector
detector = CreditCardDetector()

# Example 1: Validate a single number
is_valid = detector.luhn_check("4532148803436467")
print(f"Valid: {is_valid}")  # True

# Example 2: Identify card brand
brand = detector.identify_card_brand("4532148803436467")
print(f"Brand: {brand}")  # Visa

# Example 3: Search text for card numbers
text = """
Customer payment information:
Card: 4532-1488-0343-6467
Transaction ID: 12345
"""
findings = detector.find_card_numbers(text)
for finding in findings:
    print(f"Found: {finding['masked_number']} ({finding['card_brand']})")

# Example 4: Scan CSV programmatically
findings = detector.scan_csv("customers.csv")
detector.generate_report(findings, "report.csv")

# Example 5: Scan directory
findings = detector.scan_directory("/var/logs", extensions=['.log', '.txt'])
print(f"Total findings: {len(findings)}")
```

## Supported Card Formats

The detector recognizes various formatting styles:

```
✓ 4532148803436467           (no spaces)
✓ 4532-1488-0343-6467        (dashes)
✓ 4532 1488 0343 6467        (spaces)
✓ 378282246310005            (15-digit Amex)
✓ 6011111111111117           (16-digit Discover)
```

## Card Brand Detection

| Brand | IIN Pattern | Digits |
|-------|-------------|--------|
| Visa | 4 | 13, 16, 19 |
| Mastercard | 51-55, 2221-2720 | 16 |
| American Express | 34, 37 | 15 |
| Discover | 6011, 622126-622925, 644-649, 65 | 16 |
| Diners Club | 300-305, 36, 38 | 14 |
| JCB | 3528-3589 | 16 |

## Output Format

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
  Masked Number: 378282...0005
  Card Brand: Amex
  Format: 378282246310005
  Length: 15 digits

================================================================================
```

### CSV Report
```csv
file,row,column,line,masked_number,card_brand,original_format,length
transactions.csv,5,3,,453214...6467,Visa,4532-1488-0343-6467,16
backup.log,,,1247,378282...0005,Amex,378282246310005,15
```

## PCI-DSS Compliance Use Cases

### 1. Pre-Assessment Discovery
```bash
# Scan all systems before your assessment
python card_detector.py --directory /data --output pre_assessment.csv
```

### 2. Scope Validation (Requirement 12.5.2)
```bash
# Verify card data isn't stored in unexpected locations
python card_detector.py --directory /backups --output scope_validation.csv
```

### 3. Log Analysis (Requirement 10.2)
```bash
# Check logs for inadvertent card data logging
python card_detector.py --file /var/log/application.log
```

### 4. Data Retention Validation (Requirement 3.1)
```bash
# Find card data that should have been purged
python card_detector.py --csv old_transactions.csv
```

### 5. Third-Party Data Validation
```bash
# Verify vendor data doesn't contain unexpected CHD
python card_detector.py --directory /vendor_data
```

## Security Considerations

### What This Tool Does
✓ Detects potential card numbers using Luhn validation<br>
✓ Masks numbers in output (shows only BIN + last 4)<br>
✓ Generates reports for compliance documentation<br>
✓ Helps identify data storage you didn't know about<br>

### What This Tool Does NOT Do
✗ Store or transmit any discovered card numbers<br>
✗ Test card numbers against live payment systems<br>
✗ Guarantee 100% detection (obfuscated or encrypted data may not be found)<br>
✗ Replace proper PCI-DSS assessment by a QSA<br>

### Best Practices
1. **Run on isolated systems** - Don't run on production databases directly<br>
2. **Secure the output** - Reports contain masked numbers but should still be protected<br>
3. **Delete reports after use** - Don't keep findings longer than necessary<br>
4. **Use read-only access** - Script only reads files, but use read-only permissions<br>
5. **Log all scans** - Maintain audit trail of discovery activities<br>

## Technical Details

### False Positives
The Luhn algorithm can validate numbers that aren't actually credit cards:
- Some phone numbers
- Random number sequences
- Account numbers from other systems

**Mitigation**: The script includes IIN (card brand) validation to reduce false positives.

### False Negatives
The script may miss:
- Encrypted or hashed card numbers
- Card numbers split across multiple fields
- Obfuscated or encoded data
- Numbers stored in binary formats
- Card numbers in images or PDFs (requires OCR)

### Performance
- **CSV Files**: ~1-2 MB/second (depends on column count)
- **Text Files**: ~5-10 MB/second
- **Large Directories**: Progress shown per file

## Extending the Script

### Add Support for PDF Files
```python
# Install required library
pip install PyPDF2

# Add to scan_directory method
if file_path.suffix.lower() == '.pdf':
    findings = self.scan_pdf(str(file_path))
```

### Add Support for Excel Files
```python
# Install required library
pip install openpyxl

# Add Excel scanning method
def scan_excel(self, excel_path: str) -> List[Dict]:
    import openpyxl
    wb = openpyxl.load_workbook(excel_path)
    # Implement cell-by-cell scanning
```

### Add Real-Time Monitoring
```python
# Install required library
pip install watchdog

# Monitor directory for new files
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
```

## Testing

### Test with Known Valid Numbers
```python
# These are test numbers (will not process on real systems)
test_numbers = [
    "4532148803436467",  # Visa
    "5425233430109903",  # Mastercard
    "378282246310005",   # Amex
    "6011111111111117",  # Discover
]

detector = CreditCardDetector()
for number in test_numbers:
    assert detector.luhn_check(number), f"Failed: {number}"
    print(f"✓ {detector.identify_card_brand(number)}: {number}")
```

## Troubleshooting

### "No card numbers detected" but you know they exist
- Check file encoding (try UTF-8, Latin-1)
- Verify card numbers aren't encrypted
- Check if numbers are split across columns
- Look for unusual formatting (e.g., parentheses, extra characters)

### Too many false positives
- Review the IIN patterns in `CARD_PATTERNS`
- Add additional validation (e.g., length checks)
- Filter by context (e.g., only in fields named "card_number")

### Performance issues with large files
- Process in chunks
- Use multiprocessing for directory scans
- Filter by file size before scanning

## License

MIT License - See LICENSE file for details

## Disclaimer

This tool is provided for PCI-DSS compliance and risk management purposes only. Always follow your organization's security policies and legal requirements when handling cardholder data.

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## Support

For issues, questions, or feature requests:
- Open an issue on GitHub
- Contact: jcmunera@cybersecpro.me

## Related Resources

- [PCI Security Standards Council](https://www.pcisecuritystandards.org/)
- [PCI DSS v4.0.1 Requirements](https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0_1.pdf)
- [Luhn Algorithm on Wikipedia](https://en.wikipedia.org/wiki/Luhn_algorithm)
- [BIN Database](https://binlist.net/)

---



