from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import html
from datetime import datetime
from functions_framework import create_app

app = Flask(__name__)
CORS(app)  # Memungkinkan akses dari frontend


class SQLInjectionChecker:
    def __init__(self):
        # Daftar pola SQL injection yang umum
        self.sql_patterns = [
            # Union-based injection
            r'(\bunion\b.*\bselect\b)',
            r'(\bselect\b.*\bunion\b)',
            
            # Boolean-based blind injection
            r'(\b(and|or)\b\s*\d+\s*[=<>]\s*\d+)',
            r'(\b(and|or)\b\s*[\'"]?\w+[\'"]?\s*[=<>]\s*[\'"]?\w+[\'"]?)',
            
            # Time-based blind injection
            r'(\bwaitfor\b\s+\bdelay\b)',
            r'(\bsleep\s*\(\s*\d+\s*\))',
            r'(\bbenchmark\s*\(\s*\d+)',
            
            # Error-based injection
            r'(\bcast\s*\(\s*.*\s+as\s+.*\))',
            r'(\bconvert\s*\(\s*.*,.*\))',
            r'(\bextractvalue\s*\(\s*.*,.*\))',
            
            # Stacked queries
            r'(;\s*(drop|delete|insert|update|create)\b)',
            
            # Comment-based evasion
            r'(/\*.*\*/)',
            r'(--\s*.*)',
            r'(#.*)',
            
            # Information schema access
            r'(\binformation_schema\b)',
            r'(\bsysobjects\b)',
            r'(\bsyscolumns\b)',
            
            # String concatenation
            r'(\bconcat\s*\(\s*.*\s*\))',
            r'(\|\|)',
            
            # Hexadecimal encoding
            r'(0x[0-9a-f]+)',
            
            # Database functions
            r'(\b(user|database|version|@@version)\s*\(\s*\))',
            
            # Conditional statements
            r'(\bif\s*\(\s*.*,.*,.*\))',
            r'(\bcase\s+when\b.*\bthen\b.*\belse\b.*\bend\b)',
            
            # String functions yang mencurigakan
            r'(\bsubstring\s*\(\s*.*\s*,\s*\d+\s*,\s*\d+\s*\))',
            r'(\blength\s*\(\s*.*\s*\))',
            r'(\bchar\s*\(\s*\d+.*\))',
            
            # Escape sequences
            r'(\\\x[0-9a-f]{2})',
            r'(\\\[0-7]{3})',
        ]
        
        # Kata kunci SQL yang berbahaya
        self.dangerous_keywords = [
            'select', 'insert', 'update', 'delete', 'drop', 'create', 'alter',
            'union', 'exec', 'execute', 'sp_', 'xp_', 'script', 'javascript',
            'vbscript', 'onload', 'onerror', 'alert', 'document', 'cookie'
        ]
        
        # Karakter yang mencurigakan
        self.suspicious_chars = [
            "'", '"', ';', '--', '/*', '*/', '@@', 'char(', 'chr(', 'ascii(',
            'waitfor', 'delay', 'sleep(', 'benchmark('
        ]
    
    def check_sql_injection(self, input_string):
        """
        Memeriksa apakah input mengandung pola SQL injection
        """
        if not input_string:
            return {
                'is_malicious': False,
                'risk_level': 'low',
                'patterns_found': [],
                'details': 'Input kosong'
            }
        
        # Normalisasi input
        normalized_input = input_string.lower().strip()
        patterns_found = []
        risk_score = 0
        
        # Cek pola regex
        for pattern in self.sql_patterns:
            matches = re.findall(pattern, normalized_input, re.IGNORECASE | re.DOTALL)
            if matches:
                patterns_found.extend([f"SQL Pattern: {match}" for match in matches])
                risk_score += 10
        
        # Cek kata kunci berbahaya
        dangerous_found = []
        for keyword in self.dangerous_keywords:
            if keyword in normalized_input:
                dangerous_found.append(keyword)
                risk_score += 5
        
        # Cek karakter mencurigakan
        suspicious_found = []
        for char in self.suspicious_chars:
            if char in normalized_input:
                suspicious_found.append(char)
                risk_score += 3
        
        # Cek kombinasi quote yang mencurigakan
        single_quotes = normalized_input.count("'")
        double_quotes = normalized_input.count('"')
        if single_quotes > 2 or double_quotes > 2:
            patterns_found.append("Multiple quotes detected")
            risk_score += 8
        
        # Cek pola union select
        if 'union' in normalized_input and 'select' in normalized_input:
            patterns_found.append("UNION SELECT pattern detected")
            risk_score += 15
        
        # Tentukan level risiko
        if risk_score >= 20:
            risk_level = 'high'
            is_malicious = True
        elif risk_score >= 10:
            risk_level = 'medium'
            is_malicious = True
        elif risk_score >= 5:
            risk_level = 'low'
            is_malicious = False
        else:
            risk_level = 'safe'
            is_malicious = False
        
        # Tambahkan detail temuan
        if dangerous_found:
            patterns_found.extend([f"Dangerous keyword: {kw}" for kw in dangerous_found])
        if suspicious_found:
            patterns_found.extend([f"Suspicious character: {char}" for char in suspicious_found])
        
        return {
            'is_malicious': is_malicious,
            'risk_level': risk_level,
            'risk_score': risk_score,
            'patterns_found': patterns_found,
            'dangerous_keywords': dangerous_found,
            'suspicious_characters': suspicious_found
        }

# Inisialisasi checker
sql_checker = SQLInjectionChecker()

@app.route('/', methods=['GET'])
def home():
    """Endpoint utama untuk info API"""
    return jsonify({
        'message': 'SQL Injection Checker API',
        'version': '1.0',
        'endpoints': {
            '/check': 'POST - Check SQL injection',
            '/batch-check': 'POST - Check multiple inputs',
            '/health': 'GET - Health check'
        }
    })

@app.route('/check', methods=['POST'])
def check_sql_injection():
    """Endpoint untuk mengecek satu input"""
    try:
        data = request.get_json()
        
        if not data or 'input' not in data:
            return jsonify({
                'error': 'Missing input parameter',
                'status': 'error'
            }), 400
        
        input_text = data.get('input', '')
        
        # HTML decode jika diperlukan
        if data.get('html_decode', False):
            input_text = html.unescape(input_text)
        
        # Lakukan pemeriksaan
        result = sql_checker.check_sql_injection(input_text)
        
        response = {
            'status': 'success',
            'input': input_text,
            'timestamp': datetime.now().isoformat(),
            'result': result
        }
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'status': 'error',
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/batch-check', methods=['POST'])
def batch_check_sql_injection():
    """Endpoint untuk mengecek multiple inputs sekaligus"""
    try:
        data = request.get_json()
        
        if not data or 'inputs' not in data:
            return jsonify({
                'error': 'Missing inputs parameter',
                'status': 'error'
            }), 400
        
        inputs = data.get('inputs', [])
        
        if not isinstance(inputs, list):
            return jsonify({
                'error': 'Inputs must be an array',
                'status': 'error'
            }), 400
        
        if len(inputs) > 100:  # Limit untuk mencegah abuse
            return jsonify({
                'error': 'Too many inputs (max 100)',
                'status': 'error'
            }), 400
        
        results = []
        
        for i, input_text in enumerate(inputs):
            if isinstance(input_text, str):
                result = sql_checker.check_sql_injection(input_text)
                results.append({
                    'index': i,
                    'input': input_text,
                    'result': result
                })
            else:
                results.append({
                    'index': i,
                    'input': str(input_text),
                    'result': {
                        'is_malicious': False,
                        'risk_level': 'safe',
                        'patterns_found': [],
                        'error': 'Invalid input type'
                    }
                })
        
        # Statistik
        malicious_count = sum(1 for r in results if r['result'].get('is_malicious', False))
        safe_count = len(results) - malicious_count
        
        response = {
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
            'total_checked': len(results),
            'statistics': {
                'malicious': malicious_count,
                'safe': safe_count,
                'malicious_percentage': round((malicious_count / len(results)) * 100, 2) if results else 0
            },
            'results': results
        }
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'status': 'error',
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'service': 'SQL Injection Checker API'
    })

@app.route('/patterns', methods=['GET'])
def get_patterns():
    """Endpoint untuk melihat pola yang digunakan untuk deteksi"""
    return jsonify({
        'status': 'success',
        'patterns': {
            'sql_patterns_count': len(sql_checker.sql_patterns),
            'dangerous_keywords': sql_checker.dangerous_keywords,
            'suspicious_characters': sql_checker.suspicious_chars
        }
    })

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': 'Endpoint not found',
        'status': 'error',
        'timestamp': datetime.now().isoformat()
    }), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({
        'error': 'Method not allowed',
        'status': 'error',
        'timestamp': datetime.now().isoformat()
    }), 405

if __name__ == '__main__':
    print("🚀 Starting SQL Injection Checker API...")
    print("📋 Available endpoints:")
    print("   GET  /           - API information")
    print("   POST /check      - Check single input")
    print("   POST /batch-check - Check multiple inputs")
    print("   GET  /health     - Health check")
    print("   GET  /patterns   - View detection patterns")
    print("🌐 Server running on http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=3000)