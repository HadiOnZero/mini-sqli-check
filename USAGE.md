# SQL Injection Scanner - Usage Guide

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Basic Scan
```bash
python3 main.py -u "http://example.com/page?id=1"
```

### 3. Advanced Scan Options
```bash
# Test POST parameters
python3 main.py -u "http://example.com/login" -m POST

# Use more threads for faster scanning
python3 main.py -u "http://example.com/search?q=test" -t 10

# Save detailed report
python3 main.py -u "http://example.com/page?id=1" -o scan_report.txt

# Custom timeout for slow servers
python3 main.py -u "http://example.com/page?id=1" -T 30
```

## Common Usage Scenarios

### Scenario 1: Testing a Search Form
```bash
python3 main.py -u "http://target.com/search?q=test&category=all" -t 8
```

### Scenario 2: Testing a Login Form
```bash
python3 main.py -u "http://target.com/login" -m POST -t 5
```

### Scenario 3: Testing Multiple Parameters
```bash
python3 main.py -u "http://target.com/product?id=1&cat=electronics&sort=price" -t 10
```

### Scenario 4: Comprehensive Scan with Report
```bash
python3 main.py -u "http://target.com/page?id=1" -t 10 -T 15 -o comprehensive_report.txt
```

## Understanding the Output

### Vulnerability Found
```
[!] VULNERABILITIES FOUND!
Vulnerable Parameters: id, search

Parameter: id
Status: VULNERABLE
Errors Found:
  - Payload: '
    Error: SQL.*syntax.*MySQL
    Response Time: 0.23s
  - Payload: ' OR SLEEP(5)--
    Error: Time-based blind SQL injection (response time > 5s)
    Response Time: 5.12s
```

### No Vulnerabilities Found
```
[+] No SQL injection vulnerabilities detected
```

## Advanced Features

### 1. Multi-threading
- Use `-t` option to specify number of threads
- Recommended: 5-10 threads for most scenarios
- Higher thread count = faster scanning but more server load

### 2. Timeout Configuration
- Use `-T` option to set request timeout
- Default: 10 seconds
- Increase for slow servers or complex queries

### 3. Method Selection
- GET method: Tests URL parameters
- POST method: Tests form data parameters

### 4. Report Generation
- Automatic timestamp-based filenames if not specified
- Detailed vulnerability information
- Response times and error patterns

## Payload Categories

The scanner tests with various payload types:

### Basic Injection
- `'` (single quote)
- `''` (double single quote)
- `' OR '1'='1` (classic OR injection)

### Union-based
- `1' UNION SELECT NULL--`
- `1' UNION SELECT 1,2,3--`

### Time-based Blind
- `'; WAITFOR DELAY '0:0:5'--` (MSSQL)
- `' OR SLEEP(5)--` (MySQL)
- `' OR pg_sleep(5)--` (PostgreSQL)

### Boolean-based
- `1' AND 1=1--` (true condition)
- `1' AND 1=2--` (false condition)

## Error Detection

The scanner detects errors from multiple database systems:

### MySQL
- `SQL syntax.*MySQL`
- `Warning.*mysql_.*`
- `valid MySQL result`

### PostgreSQL
- `PostgreSQL.*ERROR`
- `Warning.*pg_.*`

### Microsoft SQL Server
- `Driver.* SQL.*Server`
- `OLE DB.* SQL Server`

### Oracle
- `Exception.*Oracle`
- `Oracle error`

### SQLite
- `SQLite.*Driver`
- `Warning.*sqlite_.*`

## Best Practices

### 1. Target Selection
- Only scan targets you own or have permission to test
- Start with non-production environments
- Inform stakeholders before scanning

### 2. Scanning Strategy
- Start with basic GET parameters
- Test POST forms separately
- Use appropriate thread counts
- Monitor server responses

### 3. Result Analysis
- Verify findings manually
- Test successful payloads manually
- Check for false positives
- Document all findings

### 4. Performance Optimization
- Use appropriate timeout values
- Adjust thread count based on server response
- Scan during low-traffic periods
- Monitor network connectivity

## Troubleshooting

### Common Issues

#### 1. Connection Timeouts
```bash
# Increase timeout
python3 main.py -u "http://slow-server.com/page?id=1" -T 30
```

#### 2. Too Many Threads
```bash
# Reduce thread count if server is overwhelmed
python3 main.py -u "http://target.com/page?id=1" -t 3
```

#### 3. False Positives
- Manually verify findings
- Check response context
- Test with different payloads

#### 4. Missing Parameters
- Ensure URL contains parameters
- Check URL encoding
- Verify parameter names

### Error Messages

#### "No parameters found in URL"
- Add parameters to the URL: `http://site.com/page?id=1&param=value`

#### "Error during scan"
- Check network connectivity
- Verify target accessibility
- Check URL format

## Integration Examples

### Bash Script Integration
```bash
#!/bin/bash
# Scan multiple URLs from file

URL_FILE="targets.txt"
REPORT_DIR="reports"

mkdir -p "$REPORT_DIR"

while IFS= read -r url; do
    echo "Scanning: $url"
    python3 main.py -u "$url" -o "$REPORT_DIR/$(date +%s)_report.txt"
done < "$URL_FILE"
```

### Python Integration
```python
import subprocess
import json

def scan_target(url, output_file=None):
    cmd = ['python3', 'main.py', '-u', url]
    if output_file:
        cmd.extend(['-o', output_file])
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr
```

## Security Considerations

### Legal Requirements
- Obtain written permission before scanning
- Follow responsible disclosure practices
- Comply with local laws and regulations
- Respect rate limits and server resources

### Ethical Guidelines
- Only scan authorized targets
- Minimize server impact
- Report findings appropriately
- Protect sensitive data

## Support and Updates

For issues, feature requests, or updates:
- Check the documentation first
- Test with the demo scanner
- Verify dependencies are installed
- Review common troubleshooting steps

Remember: This tool is for authorized security testing only. Always ensure you have explicit permission before scanning any system.