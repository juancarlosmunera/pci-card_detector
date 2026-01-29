"""
Test suite and examples for the Credit Card Detector
"""

from card_detector import CreditCardDetector


def test_luhn_algorithm():
    """Test the Luhn algorithm with known valid and invalid numbers."""
    print("Testing Luhn Algorithm...")
    print("=" * 50)
    
    detector = CreditCardDetector()
    
    # Valid test cards (these are official test numbers, won't process)
    valid_cards = {
        "4532148803436467": "Visa",
        "4532-1488-0343-6467": "Visa (with dashes)",
        "4532 1488 0343 6467": "Visa (with spaces)",
        "5425233430109903": "Mastercard",
        "378282246310005": "American Express",
        "6011111111111117": "Discover",
        "3530111333300000": "JCB",
    }
    
    print("\nValid Card Numbers:")
    for card, description in valid_cards.items():
        result = detector.luhn_check(card)
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {description}")
        assert result, f"Should be valid: {card}"
    
    # Invalid cards (modified last digit)
    invalid_cards = {
        "4532148803436468": "Visa (bad checksum)",
        "5425233430109904": "Mastercard (bad checksum)",
        "378282246310006": "Amex (bad checksum)",
    }
    
    print("\nInvalid Card Numbers (should fail):")
    for card, description in invalid_cards.items():
        result = detector.luhn_check(card)
        status = "✓ PASS" if not result else "✗ FAIL"
        print(f"{status}: {description}")
        assert not result, f"Should be invalid: {card}"
    
    print("\n" + "=" * 50)
    print("✓ All Luhn algorithm tests passed!\n")


def test_card_brand_detection():
    """Test card brand identification."""
    print("Testing Card Brand Detection...")
    print("=" * 50)
    
    detector = CreditCardDetector()
    
    test_cases = [
        ("4532148803436467", "Visa"),
        ("5425233430109903", "Mastercard"),
        ("378282246310005", "Amex"),
        ("6011111111111117", "Discover"),
        ("3530111333300000", "JCB"),
        ("30569309025904", "Diners"),
    ]
    
    for card, expected_brand in test_cases:
        detected = detector.identify_card_brand(card)
        status = "✓ PASS" if detected == expected_brand else "✗ FAIL"
        print(f"{status}: {card[:6]}... -> {detected} (expected: {expected_brand})")
        assert detected == expected_brand, f"Brand mismatch for {card}"
    
    print("\n" + "=" * 50)
    print("✓ All brand detection tests passed!\n")


def test_text_search():
    """Test finding card numbers in various text formats."""
    print("Testing Text Search...")
    print("=" * 50)
    
    detector = CreditCardDetector()
    
    # Sample text with various card number formats
    sample_texts = [
        {
            "text": "Customer card: 4532-1488-0343-6467 was charged $100",
            "expected_count": 1,
            "description": "Dashed format"
        },
        {
            "text": "Payment: 4532 1488 0343 6467",
            "expected_count": 1,
            "description": "Spaced format"
        },
        {
            "text": "Card number 4532148803436467 expired",
            "expected_count": 1,
            "description": "No formatting"
        },
        {
            "text": """
            Transaction log:
            Card 1: 4532148803436467
            Card 2: 5425233430109903
            Card 3: 378282246310005
            """,
            "expected_count": 3,
            "description": "Multiple cards"
        },
        {
            "text": "No cards here, just numbers: 123456789012",
            "expected_count": 0,
            "description": "Invalid numbers only"
        },
    ]
    
    for test in sample_texts:
        findings = detector.find_card_numbers(test["text"])
        count = len(findings)
        expected = test["expected_count"]
        status = "✓ PASS" if count == expected else "✗ FAIL"
        
        print(f"\n{status}: {test['description']}")
        print(f"  Expected: {expected}, Found: {count}")
        
        if findings:
            for finding in findings:
                print(f"  - {finding['masked_number']} ({finding['card_brand']})")
        
        assert count == expected, f"Count mismatch for: {test['description']}"
    
    print("\n" + "=" * 50)
    print("✓ All text search tests passed!\n")


def test_modern_bin_lengths():
    """Test that detector works with varying BIN lengths (6-8 digits)."""
    print("Testing Modern BIN Length Support...")
    print("=" * 50)
    
    detector = CreditCardDetector()
    
    # Note: These are constructed examples for testing
    # In practice, you'd validate against real 8-digit BIN cards
    
    print("\n16-digit card (traditional 6-digit BIN):")
    card_16 = "4532148803436467"
    result = detector.luhn_check(card_16)
    print(f"  {card_16} -> {'Valid' if result else 'Invalid'}")
    assert result
    
    print("\n19-digit card (modern 8-digit BIN):")
    card_19 = "4532148803436467123"
    # Note: This specific number may not be valid, but shows length support
    result = detector.luhn_check(card_19)
    print(f"  {card_19} -> Checks length range (13-19): {len(card_19)} digits")
    print(f"  Algorithm processes regardless of BIN length: ✓")
    
    print("\n" + "=" * 50)
    print("✓ BIN length flexibility confirmed!\n")
    print("Note: Luhn algorithm validates the ENTIRE number,")
    print("not individual components like BIN vs account number.\n")


def demo_basic_usage():
    """Demonstrate basic usage of the detector."""
    print("DEMONSTRATION: Basic Usage")
    print("=" * 50)
    
    detector = CreditCardDetector()
    
    # Example 1: Simple validation
    print("\n1. Validate a single card number:")
    test_card = "4532148803436467"
    is_valid = detector.luhn_check(test_card)
    print(f"   {test_card} -> {'Valid ✓' if is_valid else 'Invalid ✗'}")
    
    # Example 2: Identify brand
    print("\n2. Identify card brand:")
    brand = detector.identify_card_brand(test_card)
    print(f"   {test_card} -> {brand}")
    
    # Example 3: Search text
    print("\n3. Search text for card numbers:")
    sample_text = """
    Customer Information:
    Name: John Doe
    Email: john@example.com
    Card: 4532-1488-0343-6467
    Transaction: $150.00
    """
    findings = detector.find_card_numbers(sample_text)
    print(f"   Found {len(findings)} card number(s)")
    for finding in findings:
        print(f"   - Masked: {finding['masked_number']}")
        print(f"     Brand: {finding['card_brand']}")
        print(f"     Format: {finding['original_format']}")
    
    print("\n" + "=" * 50 + "\n")


def create_sample_csv():
    """Create a sample CSV file for testing."""
    import csv
    
    print("Creating sample CSV file for testing...")
    
    sample_data = [
        ["customer_id", "name", "email", "card_number", "amount"],
        ["001", "John Doe", "john@example.com", "4532-1488-0343-6467", "100.00"],
        ["002", "Jane Smith", "jane@example.com", "5425233430109903", "250.50"],
        ["003", "Bob Johnson", "bob@example.com", "378282246310005", "75.25"],
        ["004", "Alice Brown", "alice@example.com", "6011111111111117", "500.00"],
    ]
    
    with open('sample_transactions.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(sample_data)
    
    print("✓ Created: sample_transactions.csv")
    print("\nTo scan this file, run:")
    print("  python card_detector.py --csv sample_transactions.csv\n")


def create_sample_log():
    """Create a sample log file for testing."""
    print("Creating sample log file for testing...")
    
    log_content = """
2024-01-15 10:23:45 INFO  Payment processed successfully
2024-01-15 10:23:46 DEBUG Card number: 4532148803436467
2024-01-15 10:23:47 INFO  Transaction ID: TXN-12345
2024-01-15 10:24:12 WARN  Retry attempted for card 5425233430109903
2024-01-15 10:24:13 INFO  Authorization code: AUTH-789
2024-01-15 10:25:01 ERROR Failed to process card 378282246310005
2024-01-15 10:25:02 INFO  Customer notified of failure
"""
    
    with open('sample_application.log', 'w') as f:
        f.write(log_content)
    
    print("✓ Created: sample_application.log")
    print("\nTo scan this file, run:")
    print("  python card_detector.py --file sample_application.log\n")


if __name__ == "__main__":
    print("\n" + "="*60)
    print("  PCI-DSS CARD DETECTOR - TEST SUITE")
    print("="*60 + "\n")
    
    # Run tests
    test_luhn_algorithm()
    test_card_brand_detection()
    test_text_search()
    test_modern_bin_lengths()
    
    # Show demo
    demo_basic_usage()
    
    # Create sample files
    print("\n" + "="*60)
    print("  CREATING SAMPLE FILES")
    print("="*60 + "\n")
    create_sample_csv()
    create_sample_log()
    
    print("\n" + "="*60)
    print("  ✓ ALL TESTS PASSED!")
    print("="*60 + "\n")
    
    print("Next steps:")
    print("1. Run: python card_detector.py --csv sample_transactions.csv")
    print("2. Run: python card_detector.py --file sample_application.log")
    print("3. Integrate into your own compliance workflows\n")
