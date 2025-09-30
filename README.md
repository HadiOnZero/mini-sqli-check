# Mini SQL Injection Vulnerability Scanner

A lightweight Python tool for detecting SQL injection vulnerabilities in web applications. This scanner uses multiple techniques including error-based detection and time-based blind SQL injection detection.

## Features

- **Multiple SQL Injection Payloads**: Tests with 25+ common SQL injection payloads
- **Error Pattern Detection**: Identifies SQL errors from various database systems (MySQL, PostgreSQL, MSSQL, Oracle, DB2, SQLite)
- **Time-based Blind Detection**: Detects time-based blind SQL injection vulnerabilities
- **Multi-threading**: Fast scanning with configurable thread count
- **Comprehensive Reporting**: Detailed vulnerability reports with findings
- **Support for GET and POST**: Test both GET and POST parameters
- **Concurrent Parameter Testing**: Test multiple parameters simultaneously

## Installation

1. Clone or download the scanner files
2. Install required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage
```bash
python3 main.py -u "http://example.com/page?id=1"
```

### Advanced Usage
```bash
# Test POST parameters
python3 main.py -u "http://example.com/login" -m POST

# Use more threads for faster scanning
python3 main.py -u "http://example.com/search?q=test" -t 10

# Save report to file
python3 main.py -u "http://example.com/page?id=1" -o report.txt

# Enable verbose output
python3 main.py -u "http://example.com/page?id=1" -v
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-u, --url` | Target URL to scan (required) | - |
| `-m, --method` | HTTP method (GET or POST) | GET |
| `-t, --threads` | Number of threads | 5 |
| `-T, --timeout` | Request timeout in seconds | 10 |
| `-o, --output` | Output file for scan results | - |
| `-v, --verbose` | Enable verbose output | False |

## How It Works

1. **Parameter Extraction**: Automatically extracts parameters from the target URL
2. **Payload Testing**: Tests each parameter with various SQL injection payloads
3. **Error Detection**: Analyzes responses for SQL error patterns
4. **Time-based Detection**: Measures response times to detect blind SQL injection
5. **Reporting**: Generates detailed reports of findings

## Detection Methods

### Error-based Detection
The scanner looks for common SQL error messages from different database systems:
- MySQL errors
- PostgreSQL errors  
- Microsoft SQL Server errors
- Oracle errors
- IBM DB2 errors
- SQLite errors
- Generic SQL errors

### Time-based Blind Detection
Detects vulnerabilities by measuring response times when using time-delay payloads like:
- `WAITFOR DELAY` (MSSQL)
- `SLEEP()` (MySQL)
- `pg_sleep()` (PostgreSQL)

## Example Output

```
    ╔══════════════════════════════════════════════════════════════╗
    ║                  Mini SQL Injection Scanner                  ║
    ║                          Version 1.0                         ║
    ║                     Code By HadsXdevCate                     ║
    ╚══════════════════════════════════════════════════════════════╝

[*] Scanning URL: http://example.com/page?id=1
[*] Found 1 parameter(s): id

============================================================
SQL INJECTION VULNERABILITY SCAN REPORT
============================================================
URL: http://example.com/page?id=1
Method: GET
Scan Time: 2025-09-30 15:00:00
------------------------------------------------------------
[!] VULNERABILITIES FOUND!
Vulnerable Parameters: id

Parameter: id
Status: VULNERABLE
Errors Found:
  - Payload: ' OR '1'='1
    Error: SQL.*syntax.*MySQL
    Response Time: 0.23s
  - Payload: 1' OR SLEEP(5)--
    Error: Time-based blind SQL injection (response time > 5s)
    Response Time: 5.12s
```

## Live Test Targets

Here are legitimate, publicly available vulnerable web applications perfect for testing your scanner:

### 🎯 Primary Test Targets

**1. Acunetix Vulnerable Test Sites**
```bash
# Basic test
python3 main.py -u "http://testphp.vulnweb.com/search.php?test=query"

# Multi-parameter test
python3 main.py -u "http://testphp.vulnweb.com/listproducts.php?cat=1&artist=2"

# POST method test
python3 main.py -u "http://testphp.vulnweb.com/login.php" -m POST
```

**2. DVWA (Damn Vulnerable Web Application)**
```bash
python3 main.py -u "http://www.dvwa.co.uk/vulnerabilities/sqli/?id=1&Submit=Submit"
```

**3. OWASP Juice Shop**
```bash
python3 main.py -u "https://juice-shop.herokuapp.com/#/search?q=test"
```

### 🔧 Advanced Test Commands

```bash
# High-performance scan with 10 threads
python3 main.py -u "http://testphp.vulnweb.com/search.php?test=query" -t 10

# Extended timeout for slow responses
python3 main.py -u "http://testphp.vulnweb.com/search.php?test=query" -T 20

# Save detailed report
python3 main.py -u "http://testphp.vulnweb.com/search.php?test=query" -o vuln_report.txt

# Test multiple parameters simultaneously
python3 main.py -u "http://testphp.vulnweb.com/artists.php?artist=1&cat=2&test=3"
```

### 📋 Other Educational Targets

- **WebGoat**: `http://webgoat.cloudapp.net/WebGoat/attack`
- **Google Gruyere**: `https://google-gruyere.appspot.com/`
- **HackThisSite**: `https://www.hackthissite.org/missions/basic/1/`

### ⚠️ Important Notes

**Only use these targets for educational purposes:**
- ✅ **Authorized Testing**: All listed targets are designed for security testing
- ✅ **Educational Purpose**: Perfect for learning and tool validation
- ✅ **Legal Compliance**: These are intentionally vulnerable applications
- ❌ **Never test real websites** without explicit written permission

## Security Notice

This tool is designed for **authorized security testing only**. Always ensure you have permission before scanning any website or application. Unauthorized scanning may be illegal and violate terms of service.

## Limitations

- Only tests parameters present in the URL (for GET) or provided data (for POST)
- Does not perform advanced SQL injection techniques like union-based or boolean-based blind
- May generate false positives in some cases
- Requires network connectivity to the target

## Contributing

Feel free to submit issues, feature requests, or improvements to the scanner.

## License

This tool is provided for educational and authorized security testing purposes only.