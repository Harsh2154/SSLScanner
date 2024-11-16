## SSLScanner
A Python-based tool to analyze and identify weaknesses in SSL/TLS configurations, including protocol support, cipher strength, key size, certificate details, and common vulnerabilities.

## Features
  Extracts SSL/TLS certificate details (issuer, validity, subject, etc.).
  Detects protocol versions (e.g., SSLv2, SSLv3, TLSv1.1, TLSv1.2, TLSv1.3).
  Checks for weak ciphers and short key sizes.
  Validates the certificate chain.
  Detects vulnerabilities like expired certificates and weak encryption.
  Checks HSTS (HTTP Strict Transport Security) support.
  Grades the server based on SSL/TLS configuration strength.

## Requirements
  Python 3.6 or higher
  requests library for Python
  OpenSSL installed on your system

## Installation
1.Clone the Repository
  Clone this repository to your local machine:
  ```bash
  git clone https://github.com/yourusername/ssl-tls-checker.git
  ```
2.Navigate to the Project Directory
  ```bash
  cd ssl-tls-checker
  ```
3.Install Dependencies
  ```bash
  pip install requests
  ```
## Usage
1. Run the script using Python:
   ```bash
   python ssl_tls_checker.py
   ```
2. Enter the hostname (e.g., example.com) when prompted.
3. The tool will perform the analysis and display a detailed report.

## Sample Output
  ```bash
Enter the hostname (e.g., example.com): example.com
Connecting to example.com:443...
Certificate details: {...}
Protocol used: TLSv1.3
Cipher details: (TLS_AES_256_GCM_SHA384, TLSv1.3, 256)
Issuer: {...}
Certificate Status: Valid
HSTS Support: Yes
Grade: A
No common vulnerabilities detected.
  ```

## Details Checked
Certificate Details:
  Issuer
  Validity Period
  Subject
  SAN (Subject Alternative Names)
Encryption Details:
  Supported Protocols
  Cipher Strength
  Key Size
Vulnerabilities:
  Weak Protocols (e.g., SSLv2, SSLv3)
  Weak Ciphers (e.g., RC4, MD5)
  Expired or Invalid Certificates
  
HSTS Support: Checks if the server enforces HTTP Strict Transport Security.
Certificate Chain Validation: Verifies the SSL/TLS certificate chain.

## Disclaimer
This tool is intended for educational and ethical testing purposes only. Ensure you have permission before scanning third-party servers.



