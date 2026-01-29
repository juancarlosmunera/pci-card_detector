"""
PCI-DSS Cardholder Data Discovery Tool
Purpose: Detect potential credit card numbers in datasets for compliance and risk management
Uses Luhn algorithm (mod-10) for validation
"""

import re
import csv
import os
from pathlib import Path
from typing import List, Dict, Tuple
import argparse


class CreditCardDetector:
    """
    Detects and validates credit card numbers using the Luhn algorithm.
    Supports modern BIN formats (6-8 digit BINs).
    """
    
    # Card brand patterns (IIN ranges)
    CARD_PATTERNS = {
        'Visa': r'^4[0-9]{12}(?:[0-9]{3})?$',  # 13 or 16 digits
        'Mastercard': r'^5[1-5][0-9]{14}$|^2[2-7][0-9]{14}$',  # 16 digits
        'Amex': r'^3[47][0-9]{13}$',  # 15 digits
        'Discover': r'^6(?:011|5[0-9]{2})[0-9]{12}$',  # 16 digits
        'Diners': r'^3(?:0[0-5]|[68][0-9])[0-9]{11}$',  # 14 digits
        'JCB': r'^(?:2131|1800|35\d{3})\d{11}$',  # 16 digits
    }
    
    def __init__(self):
        self.findings = []
    
    def luhn_check(self, card_number: str) -> bool:
        """
        Validates a card number using the Luhn algorithm (mod-10).
        
        The Luhn algorithm:
        1. Starting from the rightmost digit (check digit), move left
        2. Double every second digit
        3. If doubling results in a number > 9, subtract 9
        4. Sum all digits
        5. If sum % 10 == 0, the number is valid
        
        Args:
            card_number: String of digits (no spaces/dashes)
            
        Returns:
            bool: True if valid per Luhn algorithm
        """
        # Remove any spaces or dashes
        card_number = re.sub(r'[\s-]', '', card_number)
        
        # Must be all digits
        if not card_number.isdigit():
            return False
        
        # Must be reasonable length (13-19 digits for modern cards)
        if len(card_number) < 13 or len(card_number) > 19:
            return False
        
        # Luhn algorithm
        digits = [int(d) for d in card_number]
        checksum = 0
        
        # Process from right to left
        for i in range(len(digits) - 1, -1, -1):
            digit = digits[i]
            
            # Double every second digit (from right)
            if (len(digits) - i) % 2 == 0:
                digit *= 2
                if digit > 9:
                    digit -= 9
            
            checksum += digit
        
        return checksum % 10 == 0
    
    def identify_card_brand(self, card_number: str) -> str:
        """
        Identifies the card brand based on IIN (Issuer Identification Number).
        Works with 6-8 digit BINs.
        
        Args:
            card_number: Validated card number
            
        Returns:
            str: Card brand name or 'Unknown'
        """
        for brand, pattern in self.CARD_PATTERNS.items():
            if re.match(pattern, card_number):
                return brand
        return 'Unknown'
    
    def find_card_numbers(self, text: str) -> List[Dict]:
        """
        Searches text for potential card numbers and validates them.
        
        Args:
            text: Text to search
            
        Returns:
            List of dicts containing found card numbers and metadata
        """
        findings = []
        
        # Pattern to find sequences of 13-19 digits (with optional spaces/dashes)
        # This matches various formats: 
        # - 4111111111111111
        # - 4111-1111-1111-1111
        # - 4111 1111 1111 1111
        pattern = r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4,7}\b'
        
        matches = re.finditer(pattern, text)
        
        for match in matches:
            candidate = match.group()
            # Clean the number
            clean_number = re.sub(r'[\s-]', '', candidate)
            
            # Validate with Luhn
            if self.luhn_check(clean_number):
                brand = self.identify_card_brand(clean_number)
                
                # Mask the number (show first 6 and last 4 for BIN identification)
                masked = f"{clean_number[:6]}...{clean_number[-4:]}"
                
                findings.append({
                    'original_format': candidate,
                    'masked_number': masked,
                    'card_brand': brand,
                    'position': match.start(),
                    'length': len(clean_number)
                })
        
        return findings
    
    def scan_csv(self, csv_path: str, delimiter: str = ',') -> List[Dict]:
        """
        Scans a CSV file for credit card numbers.
        
        Args:
            csv_path: Path to CSV file
            delimiter: CSV delimiter (default: comma)
            
        Returns:
            List of findings with location information
        """
        findings = []
        
        try:
            with open(csv_path, 'r', encoding='utf-8', errors='ignore') as file:
                reader = csv.reader(file, delimiter=delimiter)
                
                for row_num, row in enumerate(reader, start=1):
                    for col_num, cell in enumerate(row, start=1):
                        cell_findings = self.find_card_numbers(str(cell))
                        
                        for finding in cell_findings:
                            finding['file'] = csv_path
                            finding['row'] = row_num
                            finding['column'] = col_num
                            finding['cell_content'] = cell[:50]  # First 50 chars
                            findings.append(finding)
        
        except Exception as e:
            print(f"Error scanning {csv_path}: {str(e)}")
        
        return findings
    
    def scan_text_file(self, file_path: str) -> List[Dict]:
        """
        Scans a text file for credit card numbers.
        Supports .txt, .log, .json, etc.
        
        Args:
            file_path: Path to text file
            
        Returns:
            List of findings with location information
        """
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                for line_num, line in enumerate(file, start=1):
                    line_findings = self.find_card_numbers(line)
                    
                    for finding in line_findings:
                        finding['file'] = file_path
                        finding['line'] = line_num
                        finding['context'] = line.strip()[:100]  # First 100 chars
                        findings.append(finding)
        
        except Exception as e:
            print(f"Error scanning {file_path}: {str(e)}")
        
        return findings
    
    def scan_directory(self, directory: str, extensions: List[str] = None) -> List[Dict]:
        """
        Recursively scans a directory for files containing card numbers.
        
        Args:
            directory: Directory path to scan
            extensions: List of file extensions to scan (e.g., ['.csv', '.txt', '.log'])
                       If None, scans common text-based formats
            
        Returns:
            List of all findings
        """
        if extensions is None:
            extensions = ['.csv', '.txt', '.log', '.json', '.xml', '.sql']
        
        all_findings = []
        directory_path = Path(directory)
        
        for file_path in directory_path.rglob('*'):
            if file_path.is_file() and file_path.suffix.lower() in extensions:
                print(f"Scanning: {file_path}")
                
                if file_path.suffix.lower() == '.csv':
                    findings = self.scan_csv(str(file_path))
                else:
                    findings = self.scan_text_file(str(file_path))
                
                all_findings.extend(findings)
        
        return all_findings
    
    def generate_report(self, findings: List[Dict], output_path: str = None):
        """
        Generates a report of findings.
        
        Args:
            findings: List of detection findings
            output_path: Optional path to save CSV report
        """
        if not findings:
            print("\n✓ No credit card numbers detected.")
            return
        
        print(f"\n⚠ WARNING: {len(findings)} potential credit card number(s) detected!\n")
        print("=" * 80)
        
        for i, finding in enumerate(findings, start=1):
            print(f"\nFinding #{i}:")
            print(f"  File: {finding.get('file', 'N/A')}")
            
            if 'row' in finding:
                print(f"  Location: Row {finding['row']}, Column {finding['column']}")
            elif 'line' in finding:
                print(f"  Location: Line {finding['line']}")
            
            print(f"  Masked Number: {finding['masked_number']}")
            print(f"  Card Brand: {finding['card_brand']}")
            print(f"  Format: {finding['original_format']}")
            print(f"  Length: {finding['length']} digits")
        
        print("\n" + "=" * 80)
        
        # Save to CSV if requested
        if output_path:
            self.save_report_csv(findings, output_path)
            print(f"\n✓ Report saved to: {output_path}")
    
    def save_report_csv(self, findings: List[Dict], output_path: str):
        """
        Saves findings to a CSV report.
        
        Args:
            findings: List of detection findings
            output_path: Path for output CSV file
        """
        if not findings:
            return
        
        fieldnames = ['file', 'row', 'column', 'line', 'masked_number', 
                     'card_brand', 'original_format', 'length']
        
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(findings)


def main():
    """
    Main CLI interface for the card detection tool.
    """
    parser = argparse.ArgumentParser(
        description='PCI-DSS Cardholder Data Discovery Tool',
        epilog='Example: python card_detector.py --csv data.csv --output report.csv'
    )
    
    parser.add_argument('--csv', help='Scan a specific CSV file')
    parser.add_argument('--file', help='Scan a specific text file')
    parser.add_argument('--directory', help='Scan all files in a directory')
    parser.add_argument('--output', help='Save report to CSV file')
    parser.add_argument('--delimiter', default=',', help='CSV delimiter (default: comma)')
    
    args = parser.parse_args()
    
    detector = CreditCardDetector()
    findings = []
    
    if args.csv:
        print(f"Scanning CSV file: {args.csv}")
        findings = detector.scan_csv(args.csv, args.delimiter)
    
    elif args.file:
        print(f"Scanning text file: {args.file}")
        findings = detector.scan_text_file(args.file)
    
    elif args.directory:
        print(f"Scanning directory: {args.directory}")
        findings = detector.scan_directory(args.directory)
    
    else:
        parser.print_help()
        return
    
    detector.generate_report(findings, args.output)


if __name__ == "__main__":
    main()


# ============================================================================
# USAGE EXAMPLES
# ============================================================================

"""
# Example 1: Scan a single CSV file
python card_detector.py --csv transactions.csv

# Example 2: Scan a CSV with custom delimiter
python card_detector.py --csv data.tsv --delimiter $'\t'

# Example 3: Scan a log file
python card_detector.py --file application.log

# Example 4: Scan entire directory
python card_detector.py --directory /path/to/data --output findings_report.csv

# Example 5: Use as a module in your own script
from card_detector import CreditCardDetector

detector = CreditCardDetector()
text = "Customer card: 4532-1488-0343-6467"
findings = detector.find_card_numbers(text)
print(findings)

# Example 6: Test the Luhn validator
detector = CreditCardDetector()
print(detector.luhn_check("4532148803436467"))  # True (valid Visa)
print(detector.luhn_check("4532148803436468"))  # False (invalid)
"""
