# SQL Injection Scanner - Rust Version

A fast and efficient SQL injection vulnerability scanner written in Rust, based on the original Python implementation.

## Features

- **Fast Concurrent Scanning**: Uses async/await and Tokio for high-performance concurrent scanning
- **Comprehensive Payload Testing**: Tests against 29 different SQL injection payloads
- **Multiple Database Support**: Detects SQL errors from MySQL, PostgreSQL, MS SQL Server, Oracle, IBM DB2, and SQLite
- **Time-based Blind SQL Injection Detection**: Identifies time-based blind SQL injection vulnerabilities
- **GET and POST Method Support**: Tests parameters using both GET and POST methods
- **Detailed Reporting**: Generates comprehensive scan reports with vulnerability details
- **Thread-safe**: Uses proper synchronization for concurrent operations

## Installation

### Prerequisites
- Rust 1.70 or higher
- Cargo (comes with Rust)

### Build from Source
```bash
cd rust_scanner
cargo build --release
```

The compiled binary will be available at `target/release/sqliscan`

## Usage

```bash
# Basic scan
./sqliscan -u "http://example.com/page?id=1"

# POST method scan
./sqliscan -u "http://example.com/login" -m POST

# Custom threads and timeout
./sqliscan -u "http://example.com/search?q=test" -t 10 -T 15

# Save report to file
./sqliscan -u "http://example.com/page?id=1" -o report.txt

# Verbose output
./sqliscan -u "http://example.com/page?id=1" -v
```

### Command Line Options

- `-u, --url <URL>`: Target URL to scan (required)
- `-m, --method <METHOD>`: HTTP method (GET or POST, default: GET)
- `-t, --threads <THREADS>`: Number of threads (default: 5)
- `-T, --timeout <TIMEOUT>`: Request timeout in seconds (default: 10)
- `-o, --output <FILE>`: Output file for scan results
- `-v, --verbose`: Enable verbose output
- `--help`: Display help information
- `--version`: Display version information

## Examples

### Basic GET Request Scan
```bash
./sqliscan -u "http://testphp.vulnweb.com/artists.php?artist=1"
```

### POST Request Scan
```bash
./sqliscan -u "http://testphp.vulnweb.com/userinfo.php" -m POST
```

### High-Performance Scan with Custom Settings
```bash
./sqliscan -u "http://example.com/search?q=test&category=all" -t 20 -T 5 -v
```

## Output Example

```
============================================================
SQL INJECTION VULNERABILITY SCAN REPORT
============================================================
URL: http://example.com/page?id=1
Method: GET
Scan Time: 2025-10-01 10:30:45
------------------------------------------------------------
[!] VULNERABILITIES FOUND!
Vulnerable Parameters: id

Parameter: id
Status: VULNERABLE
Errors Found:
  - Payload: '
    Error: SQL syntax.*MySQL
    Response Time: 0.23s
  - Payload: ' OR '1'='1
    Error: SQL.*ERROR
    Response Time: 0.31s
----------------------------------------
```

## Technical Details

### Dependencies
- `reqwest`: HTTP client for making requests
- `tokio`: Async runtime for concurrent operations
- `clap`: Command-line argument parsing
- `regex`: Regular expression matching for error detection
- `url`: URL parsing and manipulation
- `chrono`: Date/time handling for reports
- `futures`: Async programming utilities

### Architecture
The scanner is built with a modular architecture:
- `main.rs`: CLI interface and program entry point
- `scanner.rs`: Core scanning logic and HTTP operations
- `report.rs`: Report generation and file output

### Performance
- Concurrent parameter testing using Tokio async runtime
- Configurable thread pool for parallel requests
- Efficient HTTP connection pooling with reqwest
- Memory-efficient streaming for large responses

## Security Notice

This tool is designed for security testing and should only be used on systems you own or have explicit permission to test. Unauthorized scanning may be illegal.

## License

MIT License - See LICENSE file for details

## Author

Code By HadsXdevCate

## Version History

- 1.0.0: Initial Rust version based on Python implementation