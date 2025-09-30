#!/usr/bin/env python3
"""
Test script for the SQL Injection Scanner
This script demonstrates the scanner functionality without requiring external dependencies
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_scanner_import():
    """Test if the scanner can be imported successfully"""
    try:
        # Import the scanner class
        from main import SQLInjectionScanner
        print("[+] SQLInjectionScanner imported successfully")
        return True
    except ImportError as e:
        print(f"[!] Failed to import SQLInjectionScanner: {e}")
        return False

def test_scanner_initialization():
    """Test scanner initialization"""
    try:
        from main import SQLInjectionScanner
        
        # Test with default settings
        scanner = SQLInjectionScanner()
        print("[+] Scanner initialized with default settings")
        
        # Test with custom settings
        scanner_custom = SQLInjectionScanner(timeout=15, threads=3)
        print("[+] Scanner initialized with custom settings")
        
        return True
    except Exception as e:
        print(f"[!] Failed to initialize scanner: {e}")
        return False

def test_payloads_and_patterns():
    """Test that payloads and error patterns are loaded"""
    try:
        from main import SQLInjectionScanner
        
        scanner = SQLInjectionScanner()
        
        # Check payloads
        if len(scanner.payloads) > 0:
            print(f"[+] Loaded {len(scanner.payloads)} SQL injection payloads")
        else:
            print("[!] No payloads loaded")
            return False
        
        # Check error patterns
        if len(scanner.error_patterns) > 0:
            print(f"[+] Loaded {len(scanner.error_patterns)} error patterns")
        else:
            print("[!] No error patterns loaded")
            return False
        
        # Show some example payloads
        print("\n[+] Example payloads:")
        for i, payload in enumerate(scanner.payloads[:5]):
            print(f"    {i+1}. {payload}")
        
        # Show some example error patterns
        print("\n[+] Example error patterns:")
        for i, pattern in enumerate(scanner.error_patterns[:5]):
            print(f"    {i+1}. {pattern[:50]}...")
        
        return True
    except Exception as e:
        print(f"[!] Failed to test payloads and patterns: {e}")
        return False

def test_parameter_extraction():
    """Test URL parameter extraction"""
    try:
        from main import SQLInjectionScanner
        
        scanner = SQLInjectionScanner()
        
        # Test URLs
        test_urls = [
            "http://example.com/page?id=1&name=test",
            "http://example.com/search?q=python&category=programming",
            "http://example.com/page",
            "https://test.com/login?user=admin&pass=123"
        ]
        
        print("\n[+] Testing parameter extraction:")
        for url in test_urls:
            params = scanner.extract_parameters(url)
            print(f"    URL: {url}")
            print(f"    Parameters: {params}")
            print()
        
        return True
    except Exception as e:
        print(f"[!] Failed to test parameter extraction: {e}")
        return False

def main():
    """Run all tests"""
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                SQL Injection Scanner Test                    ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    tests = [
        ("Import Test", test_scanner_import),
        ("Initialization Test", test_scanner_initialization),
        ("Payloads and Patterns Test", test_payloads_and_patterns),
        ("Parameter Extraction Test", test_parameter_extraction)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n[*] Running {test_name}...")
        if test_func():
            passed += 1
            print(f"[+] {test_name} PASSED")
        else:
            print(f"[-] {test_name} FAILED")
    
    print(f"\n{'='*50}")
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("[+] All tests passed! Scanner is ready to use.")
        print("\nTo use the scanner, run:")
        print("python3 main.py -u \"http://example.com/page?id=1\"")
    else:
        print("[!] Some tests failed. Please check the implementation.")
    
    return passed == total

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)