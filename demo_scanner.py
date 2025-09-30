#!/usr/bin/env python3
"""
Demo script for the SQL Injection Scanner
Shows how the scanner works with simulated responses
"""

import re
import time
from typing import Dict, List

class MockResponse:
    """Mock HTTP response for demonstration"""
    def __init__(self, text: str, status_code: int = 200):
        self.text = text
        self.status_code = status_code

class DemoSQLInjectionScanner:
    """Demo version of SQL injection scanner with simulated responses"""
    
    def __init__(self):
        # Common SQL injection payloads
        self.payloads = [
            "'",
            "''",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR 1=1--",
            "1' OR 1=1--",
            "1' UNION SELECT NULL--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' OR SLEEP(5)--"
        ]
        
        # SQL error patterns to detect
        self.error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"PostgreSQL.*ERROR",
            r"Driver.* SQL.*Server",
            r"Oracle error",
            r"SQLite.*Driver",
            r"SQL.*ERROR",
            r"Unknown column",
            r"Invalid SQL",
            r"database error"
        ]
        
        # Simulated vulnerable responses
        self.vulnerable_responses = [
            "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''''' at line 1",
            "Warning: mysql_fetch_array() expects parameter 1 to be resource, boolean given in /var/www/html/page.php on line 25",
            "Microsoft OLE DB Provider for SQL Server error '80040e14'",
            "ORA-00933: SQL command not properly ended",
            "SQLite error: near \"'\": syntax error",
            "Database error: Invalid SQL syntax"
        ]
        
        # Simulated safe responses
        self.safe_responses = [
            "Page loaded successfully",
            "No results found",
            "Invalid input",
            "Please try again",
            "Access denied",
            "Login failed"
        ]
    
    def simulate_request(self, payload: str) -> MockResponse:
        """Simulate HTTP request with different responses based on payload"""
        # Simulate vulnerable responses for specific payloads
        vulnerable_payloads = ["'", "' OR '1'='1", "1' OR 1=1--"]
        
        if any(vuln in payload for vuln in vulnerable_payloads):
            # Return vulnerable response
            response_text = self.vulnerable_responses[
                hash(payload) % len(self.vulnerable_responses)
            ]
            return MockResponse(response_text)
        else:
            # Return safe response
            response_text = self.safe_responses[
                hash(payload) % len(self.safe_responses)
            ]
            return MockResponse(response_text)
    
    def test_payload(self, payload: str) -> Dict:
        """Test a single payload against simulated responses"""
        print(f"    Testing payload: {payload}")
        
        # Simulate request
        response = self.simulate_request(payload)
        
        # Check for SQL errors in response
        vulnerabilities_found = []
        response_text = response.text.lower()
        
        for pattern in self.error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                vulnerabilities_found.append({
                    'payload': payload,
                    'error_pattern': pattern,
                    'response_snippet': response.text[:100] + "..." if len(response.text) > 100 else response.text
                })
                break  # Only report first match for demo
        
        time.sleep(0.1)  # Small delay for realism
        
        return {
            'payload': payload,
            'vulnerable': len(vulnerabilities_found) > 0,
            'vulnerabilities': vulnerabilities_found,
            'response_code': response.status_code
        }
    
    def scan_parameter(self, param_name: str = "id") -> Dict:
        """Demo scan of a single parameter"""
        print(f"\n[*] Scanning parameter: {param_name}")
        print("-" * 40)
        
        results = {
            'parameter': param_name,
            'payloads_tested': 0,
            'vulnerabilities_found': [],
            'vulnerable': False
        }
        
        for payload in self.payloads:
            result = self.test_payload(payload)
            results['payloads_tested'] += 1
            
            if result['vulnerable']:
                results['vulnerable'] = True
                results['vulnerabilities_found'].extend(result['vulnerabilities'])
        
        return results
    
    def generate_demo_report(self, results: Dict) -> str:
        """Generate a demo report"""
        report = []
        report.append("=" * 60)
        report.append("SQL INJECTION VULNERABILITY DEMO REPORT")
        report.append("=" * 60)
        report.append(f"Parameter: {results['parameter']}")
        report.append(f"Payloads Tested: {results['payloads_tested']}")
        report.append(f"Scan Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("-" * 60)
        
        if results['vulnerable']:
            report.append("[!] VULNERABILITIES FOUND!")
            report.append(f"Vulnerabilities Found: {len(results['vulnerabilities_found'])}")
            report.append("")
            
            for i, vuln in enumerate(results['vulnerabilities_found'], 1):
                report.append(f"Vulnerability #{i}:")
                report.append(f"  Payload: {vuln['payload']}")
                report.append(f"  Error Pattern: {vuln['error_pattern']}")
                report.append(f"  Response: {vuln['response_snippet']}")
                report.append("")
        else:
            report.append("[+] No SQL injection vulnerabilities detected")
        
        return "\n".join(report)

def main():
    """Run demo scan"""
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║           SQL Injection Scanner Demo                         ║
    ║                    Version 1.0                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    print("[*] Starting demo scan...")
    print("[*] This demo uses simulated responses to demonstrate scanner functionality")
    print("[*] In real usage, the scanner would make actual HTTP requests")
    
    # Initialize demo scanner
    scanner = DemoSQLInjectionScanner()
    
    # Show available payloads
    print(f"\n[*] Available payloads: {len(scanner.payloads)}")
    for i, payload in enumerate(scanner.payloads, 1):
        print(f"    {i:2d}. {payload}")
    
    # Show error patterns
    print(f"\n[*] Error detection patterns: {len(scanner.error_patterns)}")
    for i, pattern in enumerate(scanner.error_patterns[:10], 1):
        print(f"    {i:2d}. {pattern[:40]}...")
    if len(scanner.error_patterns) > 10:
        print(f"    ... and {len(scanner.error_patterns) - 10} more patterns")
    
    # Run demo scan
    results = scanner.scan_parameter("id")
    
    # Generate and display report
    report = scanner.generate_demo_report(results)
    print("\n" + report)
    
    # Show summary
    print("\n" + "=" * 60)
    print("DEMO SUMMARY")
    print("=" * 60)
    print(f"Total payloads tested: {results['payloads_tested']}")
    print(f"Vulnerabilities found: {len(results['vulnerabilities_found'])}")
    print(f"Parameter vulnerable: {'YES' if results['vulnerable'] else 'NO'}")
    
    if results['vulnerable']:
        print("\n[!] The parameter appears to be vulnerable to SQL injection!")
        print("[*] In a real scan, you would investigate these findings further.")
    else:
        print("\n[+] No obvious SQL injection vulnerabilities detected.")
        print("[*] This doesn't guarantee the parameter is completely safe.")
    
    print("\n[*] Demo completed!")
    print("[*] To run a real scan, use: python3 main.py -u \"http://target.com/page?id=1\"")

if __name__ == '__main__':
    main()