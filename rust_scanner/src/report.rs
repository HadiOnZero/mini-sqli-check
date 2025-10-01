use crate::scanner::{ScanResults, ParameterResult};
use chrono::Local;
use std::fs::File;
use std::io::Write;

pub struct ReportGenerator;

impl ReportGenerator {
    pub fn new() -> Self {
        Self
    }

    pub fn generate_report(&self, results: &ScanResults) -> String {
        let mut report = Vec::new();
        
        report.push("=".repeat(60));
        report.push("SQL INJECTION VULNERABILITY SCAN REPORT".to_string());
        report.push("=".repeat(60));
        report.push(format!("URL: {}", results.url));
        report.push(format!("Method: {}", results.method));
        report.push(format!("Scan Time: {}", Local::now().format("%Y-%m-%d %H:%M:%S")));
        report.push("-".repeat(60));
        
        if results.vulnerable {
            report.push("[!] VULNERABILITIES FOUND!".to_string());
            report.push(format!("Vulnerable Parameters: {}", results.vulnerable_parameters.join(", ")));
            report.push("".to_string());
            
            for param_result in &results.parameters_tested {
                if param_result.vulnerable {
                    report.push(format!("Parameter: {}", param_result.parameter));
                    report.push("Status: VULNERABLE".to_string());
                    report.push("Errors Found:".to_string());
                    for error in &param_result.errors_found {
                        report.push(format!("  - Payload: {}", error.payload));
                        report.push(format!("    Error: {}", error.error_pattern));
                        report.push(format!("    Response Time: {:.2}s", error.response_time));
                    }
                    report.push("-".repeat(40));
                }
            }
        } else {
            report.push("[+] No SQL injection vulnerabilities detected".to_string());
        }
        
        report.join("\n")
    }

    pub fn save_report(&self, results: &ScanResults, filename: &str) -> Result<(), Box<dyn std::error::Error>> {
        let report = self.generate_report(results);
        let mut file = File::create(filename)?;
        file.write_all(report.as_bytes())?;
        Ok(())
    }
}

impl Default for ReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}