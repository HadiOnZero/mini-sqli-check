use clap::Parser;
use std::time::Duration;
use tokio;

mod scanner;
mod report;

use scanner::SQLInjectionScanner;
use report::ReportGenerator;

#[derive(Parser)]
#[command(name = "sqliscan")]
#[command(about = "Mini SQL Injection Vulnerability Scanner - Rust Version")]
#[command(version = "1.0.0")]
#[command(author = "Code By HadsXdevCate")]
struct Args {
    #[arg(short, long, help = "Target URL to scan")]
    url: String,
    
    #[arg(short, long, default_value = "GET", help = "HTTP method (GET or POST)")]
    method: String,
    
    #[arg(short, long, default_value = "5", help = "Number of threads")]
    threads: usize,
    
    #[arg(short = 'T', long, default_value = "10", help = "Request timeout in seconds")]
    timeout: u64,
    
    #[arg(short, long, help = "Output file for scan results")]
    output: Option<String>,
    
    #[arg(short, long, help = "Enable verbose output")]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    // Validate URL
    if !args.url.starts_with("http://") && !args.url.starts_with("https://") {
        eprintln!("[!] Error: URL must start with http:// or https://");
        std::process::exit(1);
    }
    
    // Validate method
    let method = args.method.to_uppercase();
    if method != "GET" && method != "POST" {
        eprintln!("[!] Error: Method must be GET or POST");
        std::process::exit(1);
    }
    
    println!(r#"
    ╔══════════════════════════════════════════════════════════════╗
    ║                  Mini SQL Injection Scanner                  ║
    ║                          Version 1.0                         ║
    ║                     Code By HadsXdevCate                     ║
    ╚══════════════════════════════════════════════════════════════╝
    "#);
    
    // Initialize scanner
    let scanner = SQLInjectionScanner::new(
        Duration::from_secs(args.timeout),
        args.threads,
        args.verbose,
    );
    
    println!("[*] Scanning URL: {}", args.url);
    
    // Start scanning
    match scanner.scan_url(&args.url, &method).await {
        Ok(results) => {
            // Generate and display report
            let report_generator = ReportGenerator::new();
            let report = report_generator.generate_report(&results);
            println!("\n{}", report);
            
            // Save report if output file specified
            if let Some(output_file) = args.output {
                report_generator.save_report(&results, &output_file)?;
                println!("[*] Report saved to: {}", output_file);
            }
            
            // Exit with appropriate code
            if results.vulnerable {
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("[!] Error during scan: {}", e);
            std::process::exit(1);
        }
    }
    
    Ok(())
}