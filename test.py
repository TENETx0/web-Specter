def main():
    """Main function"""
    try:
        # Clear screen
        os.system('cls' if os.name == 'nt' else '            print(f"  {Colors.FAIL}[!] Error: {str(e)}{Colors.ENDC}")

    def check_cors_security(self):
        """Check CORS and Cookie Security"""
        print(f"\n{Colors.OKCYAN}[*] Analyzing CORS & Cookie Security...{Colors.ENDC}")
        try:
            # Test CORS
            response = self.session.get(self.target_url, verify=False, timeout=10)
            
            # Check CORS headers
            cors_headers = {
                'Access-Control-Allow-Origin': response.headers.get('Access-Control-Allow-Origin', 'Not Set'),
                'Access-Control-Allow-Credentials': response.headers.get('Access-Control-Allow-Credentials', 'Not Set'),
                'Access-Control-Allow-Methods': response.headers.get('Access-Control-Allow-Methods', 'Not Set'),
                'Access-Control-Allow-Headers': response.headers.get('Access-Control-Allow-Headers', 'Not Set'),
                'Access-Control-Max-Age': response.headers.get('Access-Control-Max-Age', 'Not Set')
            }
            
            self.results['cors_security'] = cors_headers
            
            # Check for dangerous CORS configurations
            if cors_headers['Access-Control-Allow-Origin'] == '*':
                print(f"  {Colors.WARNING}[!] Dangerous: CORS allows all origins (*){Colors.ENDC}")
            elif cors_headers['Access-Control-Allow-Origin'] != 'Not Set':
                print(f"  {Colors.OKGREEN}[+] CORS Origin: {cors_headers['Access-Control-Allow-Origin']}{Colors.ENDC}")
            
            if cors_headers['Access-Control-Allow-Credentials'] == 'true':
                print(f"  {Colors.WARNING}[!] CORS allows credentials{Colors.ENDC}")
            
            # Check cookies
            if response.cookies:
                for cookie in response.cookies:
                    cookie_info = {
                        'name': cookie.name,
                        'secure': cookie.secure,
                        'httponly': cookie.has_nonstandard_attr('HttpOnly'),
                        'samesite': cookie.get_nonstandard_attr('SameSite') or 'Not Set',
                        'domain': cookie.domain,
                        'path': cookie.path
                    }
                    self.results['cookie_security'].append(cookie_info)
                    
                    # Check for security issues
                    if not cookie.secure:
                        print(f"  {Colors.WARNING}[-] Cookie '{cookie.name}' missing Secure flag{Colors.ENDC}")
                    if not cookie.has_nonstandard_attr('HttpOnly'):
                        print(f"  {Colors.WARNING}[-] Cookie '{cookie.name}' missing HttpOnly flag{Colors.ENDC}")
                    if not cookie.get_nonstandard_attr('SameSite'):
                        print(f"  {Colors.WARNING}[-] Cookie '{cookie.name}' missing SameSite attribute{Colors.ENDC}")
                    
                print(f"  {Colors.OKGREEN}[+] Analyzed {len(response.cookies)} cookies{Colors.ENDC}")
            else:
                print(f"  {Colors.OKGREEN}[+] No cookies found{Colors.ENDC}")
                
        except Exception as e:
            print(f"  {Colors.FAIL}[!] Error: {str(e)}{Colors.ENDC}")

    def detect_api_keys(self):
        """Detect API Keys and Secrets"""
        print(f"\n{Colors.OKCYAN}[*] Detecting API Keys & Secrets...{Colors.ENDC}")
        try:
            response = self.session.get(self.target_url, verify=False, timeout=10)
            content = response.text
            
            # Comprehensive API key patterns
            api_patterns = {
                'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
                'Google Cloud Platform API Key': r'AIza[0-9A-Za-z\-_]{35}',
                'Google OAuth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
                'Firebase': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
                'AWS Access Key ID': r'AKIA[0-9A-Z]{16}',
                'AWS Secret Key': r'[0-9a-zA-Z/+=]{40}',
                'Amazon MWS Auth Token': r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                'Facebook Access Token': r'EAACEdEose0cBA[0-9A-Za-z]+',
                'Facebook OAuth': r'[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*[\'|"][0-9a-f]{32}[\'|"]',
                'GitHub': r'[g|G][i|I][t|T][h|H][u|U][b|B].*[\'|"][0-9a-zA-Z]{35,40}[\'|"]',
                'Generic API Key': r'[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*[\'|"][0-9a-zA-Z]{32,45}[\'|"]',
                'Generic Secret': r'[s|S][e|E][c|C][r|R][e|E][t|T].*[\'|"][0-9a-zA-Z]{32,45}[\'|"]',
                'Heroku API Key': r'[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
                'LinkedIn API Key': r'[l|L][i|I][n|N][k|K][e|E][d|D][i|I][n|N].*[\'|"][0-9a-z]{16}[\'|"]',
                'Mailchimp API Key': r'[0-9a-f]{32}-us[0-9]{1,2}',
                'Mailgun API Key': r'key-[0-9a-zA-Z]{32}',
                'PayPal Braintree Access Token': r'access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}',
                'Picatic API Key': r'sk_live_[0-9a-z]{32}',
                'Slack Token': r'xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}',
                'Slack Webhook': r'https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
                'Stripe API Key': r'sk_live_[0-9a-zA-Z]{24}',
                'Stripe Restricted API Key': r'rk_live_[0-9a-zA-Z]{24}',
                'Square Access Token': r'sq0atp-[0-9A-Za-z\\-_]{22}',
                'Square OAuth Secret': r'sq0csp-[0-9A-Za-z\\-_]{43}',
                'Telegram Bot API Key': r'[0-9]+:AA[0-9A-Za-z\\-_]{33}',
                'Twilio API Key': r'SK[0-9a-fA-F]{32}',
                'Twitter Access Token': r'[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}',
                'Twitter OAuth': r'[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[\'|"][0-9a-zA-Z]{35,44}[\'|"]',
                'JWT Token': r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
                'Private Key': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
                'Base64 Encoded Key': r'[A-Za-z0-9+/]{40,}={0,2}'
            }
            
            found_keys = []
            for key_type, pattern in api_patterns.items():
                matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                if matches:
                    for match in matches[:3]:  # Limit to 3 matches per type
                        # Mask the key for security
                        if len(str(match)) > 10:
                            masked = str(match)[:6] + '***' + str(match)[-4:]
                        else:
                            masked = '***'
                        found_keys.append({
                            'type': key_type,
                            'masked_value': masked,
                            'length': len(str(match))
                        })
                        print(f"  {Colors.WARNING}[!] Found {key_type}: {masked}{Colors.ENDC}")
            
            self.results['api_keys'] = found_keys
            
            if found_keys:
                print(f"  {Colors.WARNING}[!] Total API Keys/Secrets found: {len(found_keys)}{Colors.ENDC}")
            else:
                print(f"  {Colors.OKGREEN}[+] No API keys or secrets detected{Colors.ENDC}")
                
        except Exception as e:
            print(f"  {Colors.FAIL}[!] Error: {str(e)}{Colors.ENDC}")

    def enumerate_subdomains(self):
        """Enumerate subdomains"""
        print(f"\n{Colors.OKCYAN}[*] Enumerating Subdomains...{Colors.ENDC}")
        subdomains = []
        
        # Common subdomain prefixes
        subdomain_prefixes = [
            'www', 'mail', 'ftp', 'admin', 'blog', 'webmail', 'server',
            'ns', 'vpn', 'api', 'secure', 'shop', 'test', 'portal',
            'dev', 'staging', 'prod', 'production', 'stage', 'demo',
            'app', 'apps', 'cdn', 'media', 'assets', 'static', 'img',
            'images', 'video', 'help', 'support', 'docs', 'documentation',
            'forum', 'forums', 'news', 'beta', 'alpha', 'mobile', 'm',
            'api-v1', 'api-v2', 'v1', 'v2', 'v3', 'web', 'online',
            'services', 'service', 'gateway', 'auth', 'oauth', 'login',
            'signin', 'signup', 'register', 'account', 'accounts', 'my',
            'dashboard', 'panel', 'cpanel', 'ssh', 'git', 'gitlab',
            'jenkins', 'jira', 'confluence', 'wiki', 'kb', 'knowledge',
            'db', 'database', 'mysql', 'postgres', 'redis', 'mongo',
            'elasticsearch', 'kibana', 'grafana', 'monitoring', 'metrics',
            'logs', 'sentry', 'status', 'health', 'ping', 'api-docs'
        ]
        
        # Extract base domain
        base_domain = self.domain
        if base_domain.startswith('www.'):
            base_domain = base_domain[4:]
        
        # Try to resolve common subdomains
        for prefix in subdomain_prefixes:
            subdomain = f"{prefix}.{base_domain}"
            try:
                answers = dns.resolver.resolve(subdomain, 'A')
                if answers:
                    ip = str(answers[0])
                    subdomains.append({
                        'subdomain': subdomain,
                        'ip': ip
                    })
                    print(f"  {Colors.OKGREEN}[+] Found: {subdomain} -> {ip}{Colors.ENDC}")
            except:
                pass
        
        # Also check for wildcard subdomains
        try:
            random_subdomain = f"randomnonexistent{int(time.time())}.{base_domain}"
            dns.resolver.resolve(random_subdomain, 'A')
            print(f"  {Colors.WARNING}[!] Wildcard subdomain detected{Colors.ENDC}")
            self.results['subdomains'].append({
                'subdomain': '*.{}'.format(base_domain),
                'ip': 'Wildcard'
            })
        except:
            pass
        
        self.results['subdomains'].extend(subdomains)
        
        if subdomains:
            print(f"  {Colors.OKGREEN}[+] Total subdomains found: {len(subdomains)}{Colors.ENDC}")
        else:
            print(f"  {Colors.WARNING}[-] No subdomains found{Colors.ENDC}")

    def analyze_robots_txt(self):
        """Analyze robots.txt file"""
        print(f"\n{Colors.OKCYAN}[*] Analyzing robots.txt...{Colors.ENDC}")
        try:
            robots_url = urljoin(self.target_url, '/robots.txt')
            response = self.session.get(robots_url, verify=False, timeout=10)
            
            if response.status_code == 200:
                content = response.text
                self.results['robots_analysis'] = {
                    'exists': True,
                    'content': content[:1000],  # Store first 1000 chars
                    'disallowed_paths': [],
                    'allowed_paths': [],
                    'sitemaps': [],
                    'crawl_delay': None,
                    'user_agents': []
                }
                
                # Parse robots.txt
                lines = content.split('\n')
                current_user_agent = None
                
                for line in lines:
                    line = line.strip()
                    if line.startswith('User-agent:'):
                        user_agent = line.split(':', 1)[1].strip()
                        if user_agent not in self.results['robots_analysis']['user_agents']:
                            self.results['robots_analysis']['user_agents'].append(user_agent)
                        current_user_agent = user_agent
                    elif line.startswith('Disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path and path not in self.results['robots_analysis']['disallowed_paths']:
                            self.results['robots_analysis']['disallowed_paths'].append(path)
                            print(f"  {Colors.WARNING}[-] Disallowed: {path}{Colors.ENDC}")
                    elif line.startswith('Allow:'):
                        path = line.split(':', 1)[1].strip()
                        if path and path not in self.results['robots_analysis']['allowed_paths']:
                            self.results['robots_analysis']['allowed_paths'].append(path)
                            print(f"  {Colors.OKGREEN}[+] Allowed: {path}{Colors.ENDC}")
                    elif line.startswith('Sitemap:'):
                        sitemap = line.split(':', 1)[1].strip()
                        if sitemap:
                            self.results['robots_analysis']['sitemaps'].append(sitemap)
                            print(f"  {Colors.OKGREEN}[+] Sitemap: {sitemap}{Colors.ENDC}")
                    elif line.startswith('Crawl-delay:'):
                        delay = line.split(':', 1)[1].strip()
                        self.results['robots_analysis']['crawl_delay'] = delay
                        print(f"  {Colors.OKGREEN}[+] Crawl-delay: {delay}{Colors.ENDC}")
                
                print(f"  {Colors.OKGREEN}[+] Found {len(self.results['robots_analysis']['disallowed_paths'])} disallowed paths{Colors.ENDC}")
                print(f"  {Colors.OKGREEN}[+] Found {len(self.results['robots_analysis']['sitemaps'])} sitemaps{Colors.ENDC}")
            else:
                self.results['robots_analysis']['exists'] = False
                print(f"  {Colors.WARNING}[-] robots.txt not found (Status: {response.status_code}){Colors.ENDC}")
                
        except Exception as e:
            self.results['robots_analysis']['exists'] = False
            print(f"  {Colors.FAIL}[!] Error: {str(e)}{Colors.ENDC}")

    def detect_plugins(self):
        """Detect CMS plugins and extensions"""
        print(f"\n{Colors.OKCYAN}[*] Detecting Plugins & Extensions...{Colors.ENDC}")
        plugins = []
        
        try:
            response = self.session.get(self.target_url, verify=False, timeout=10)
            content = response.text.lower()
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # WordPress plugins
            wp_plugin_patterns = [
                r'/wp-content/plugins/([^/]+)/',
                r'wp-content/plugins/([^/]+)/[^/]+\.(?:js|css)',
            ]
            
            for pattern in wp_plugin_patterns:
                matches = re.findall(pattern, content)
                for match in set(matches):
                    if match and match not in [p['name'] for p in plugins]:
                        plugins.append({
                            'name': match,
                            'type': 'WordPress Plugin',
                            'cms': 'WordPress'
                        })
                        print(f"  {Colors.OKGREEN}[+] WordPress Plugin: {match}{Colors.ENDC}")
            
            # Joomla extensions
            joomla_patterns = [
                r'/components/com_([^/]+)/',
                r'/modules/mod_([^/]+)/',
                r'/plugins/([^/]+)/',
            ]
            
            for pattern in joomla_patterns:
                matches = re.findall(pattern, content)
                for match in set(matches):
                    if match and match not in [p['name'] for p in plugins]:
                        plugins.append({
                            'name': match,
                            'type': 'Joomla Extension',
                            'cms': 'Joomla'
                        })
                        print(f"  {Colors.OKGREEN}[+] Joomla Extension: {match}{Colors.ENDC}")
            
            # Drupal modules
            drupal_patterns = [
                r'/modules/([^/]+)/',
                r'/sites/all/modules/([^/]+)/',
                r'/sites/default/modules/([^/]+)/',
            ]
            
            for pattern in drupal_patterns:
                matches = re.findall(pattern, content)
                for match in set(matches):
                    if match and match not in [p['name'] for p in plugins]:
                        plugins.append({
                            'name': match,
                            'type': 'Drupal Module',
                            'cms': 'Drupal'
                        })
                        print(f"  {Colors.OKGREEN}[+] Drupal Module: {match}{Colors.ENDC}")
            
            # Browser plugins/extensions mentioned
            browser_plugins = {
                'jquery': 'jQuery',
                'bootstrap': 'Bootstrap',
                'font-awesome': 'Font Awesome',
                'fontawesome': 'Font Awesome',
                'google-analytics': 'Google Analytics',
                'google-tag-manager': 'Google Tag Manager',
                'facebook-pixel': 'Facebook Pixel',
                'hotjar': 'Hotjar',
                'intercom': 'Intercom',
                'drift': 'Drift',
                'crisp': 'Crisp',
                'tawk': 'Tawk.to',
                'zendesk': 'Zendesk',
                'freshchat': 'Freshchat',
                'livechat': 'LiveChat',
                'olark': 'Olark',
                'uservoice': 'UserVoice',
                'disqus': 'Disqus',
                'addthis': 'AddThis',
                'sharethis': 'ShareThis',
                'recaptcha': 'reCAPTCHA',
                'cloudflare': 'Cloudflare',
                'sucuri': 'Sucuri',
                'wordpress': 'WordPress',
                'shopify': 'Shopify',
                'wix': 'Wix',
                'squarespace': 'Squarespace',
                'weebly': 'Weebly',
                'godaddy': 'GoDaddy',
                'elementor': 'Elementor',
                'divi': 'Divi',
                'wpforms': 'WPForms',
                'contact-form-7': 'Contact Form 7',
                'woocommerce': 'WooCommerce',
                'yoast': 'Yoast SEO',
                'jetpack': 'Jetpack',
                'akismet': 'Akismet',
                'wordfence': 'Wordfence',
                'w3-total-cache': 'W3 Total Cache',
                'wp-super-cache': 'WP Super Cache'
            }
            
            for plugin_key, plugin_name in browser_plugins.items():
                if plugin_key in content:
                    plugins.append({
                        'name': plugin_name,
                        'type': 'Third-party Service',
                        'cms': 'Universal'
                    })
                    print(f"  {Colors.OKGREEN}[+] Service/Library: {plugin_name}{Colors.ENDC}")
            
            self.results['plugins'] = plugins
            
            if plugins:
                print(f"  {Colors.OKGREEN}[+] Total plugins/extensions found: {len(plugins)}{Colors.ENDC}")
            else:
                print(f"  {Colors.WARNING}[-] No plugins detected{Colors.ENDC}")
                
        except Exception as e:
            print(f"  {Colors.FAIL}[!] Error: {str(e)}{Colors.ENDC}")

    def detect_encryption(self):
        """Detect encryption and security implementations"""
        print(f"\n{Colors.OKCYAN}[*] Detecting Encryption & Security Implementations...{Colors.ENDC}")
        try:
            response = self.session.get(self.target_url, verify=False, timeout=10)
            content = response.text.lower()
            headers = response.headers
            
            encryption_info = {
                'ssl_tls': False,
                'hsts': False,
                'certificate_transparency': False,
                'public_key_pins': False,
                'csp_nonces': False,
                'sri_hashes': False,
                'encrypted_forms': [],
                'crypto_libraries': [],
                'security_headers_score': 0
            }
            
            # Check SSL/TLS
            if self.target_url.startswith('https://'):
                encryption_info['ssl_tls'] = True
                print(f"  {Colors.OKGREEN}[+] SSL/TLS encryption enabled{Colors.ENDC}")
                
                # Check TLS version (requires ssl module)
                try:
                    context = ssl.create_default_context()
                    with socket.create_connection((self.domain, 443), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                            cipher = ssock.cipher()
                            if cipher:
                                print(f"  {Colors.OKGREEN}[+] Cipher Suite: {cipher[0]}{Colors.ENDC}")
                                print(f"  {Colors.OKGREEN}[+] Protocol: {cipher[1]}{Colors.ENDC}")
                except:
                    pass
            
            # Check HSTS
            if 'Strict-Transport-Security' in headers:
                encryption_info['hsts'] = True
                encryption_info['security_headers_score'] += 1
                print(f"  {Colors.OKGREEN}[+] HSTS enabled: {headers['Strict-Transport-Security'][:50]}...{Colors.ENDC}")
            
            # Check Certificate Transparency
            if 'Expect-CT' in headers:
                encryption_info['certificate_transparency'] = True
                encryption_info['security_headers_score'] += 1
                print(f"  {Colors.OKGREEN}[+] Certificate Transparency enabled{Colors.ENDC}")
            
            # Check Public Key Pinning
            if 'Public-Key-Pins' in headers or 'Public-Key-Pins-Report-Only' in headers:
                encryption_info['public_key_pins'] = True
                encryption_info['security_headers_score'] += 1
                print(f"  {Colors.OKGREEN}[+] Public Key Pinning enabled{Colors.ENDC}")
            
            # Check for CSP nonces
            if 'Content-Security-Policy' in headers:
                csp = headers['Content-Security-Policy']
                if 'nonce-' in csp:
                    encryption_info['csp_nonces'] = True
                    print(f"  {Colors.OKGREEN}[+] CSP with nonces detected{Colors.ENDC}")
            
            # Check for SRI (Subresource Integrity)
            if 'integrity=' in content:
                encryption_info['sri_hashes'] = True
                print(f"  {Colors.OKGREEN}[+] Subresource Integrity (SRI) hashes found{Colors.ENDC}")
            
            # Detect crypto libraries
            crypto_libs = {
                'crypto-js': 'CryptoJS',
                'sjcl': 'Stanford Javascript Crypto Library',
                'forge': 'Forge',
                'bcrypt': 'bcrypt',
                'scrypt': 'scrypt',
                'pbkdf2': 'PBKDF2',
                'aes': 'AES encryption',
                'rsa': 'RSA encryption',
                'sha256': 'SHA-256 hashing',
                'sha512': 'SHA-512 hashing',
                'md5': 'MD5 hashing (weak)',
                'base64': 'Base64 encoding',
                'jwt': 'JSON Web Tokens',
                'oauth': 'OAuth',
                'saml': 'SAML'
            }
            
            for lib_key, lib_name in crypto_libs.items():
                if lib_key in content:
                    encryption_info['crypto_libraries'].append(lib_name)
                    print(f"  {Colors.OKGREEN}[+] Crypto/Security: {lib_name}{Colors.ENDC}")
            
            # Check for encrypted form submissions
            soup = BeautifulSoup(response.text, #!/usr/bin/env python3
"""
WebSpec - Advanced Web Information Gathering Tool
Compatible with Kali Linux and Windows
Author: Security Research Tool
"""

import requests
import ssl
import socket
import whois
import dns.resolver
import re
import json
import base64
import hashlib
import time
import sys
import os
import threading
import urllib3
from datetime import datetime
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings
import subprocess
import platform

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")

class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class WebSpec:
    def __init__(self, target_url):
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.domain = self.parsed_url.netloc
        self.results = {
            'target': target_url,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'security_headers': {},
            'ssl_info': {},
            'whois_info': {},
            'discovered_paths': [],
            'cms_detection': {},
            'technologies': {},
            'dns_records': {},
            'urls': [],
            'third_party': [],
            'public_assets': [],
            'js_analysis': {},
            'metadata': {}
        }
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })
        
        # Comprehensive wordlists
        self.path_wordlist = [
            # Admin paths
            '/admin', '/administrator', '/admin.php', '/login', '/wp-admin',
            '/cpanel', '/phpmyadmin', '/adminer', '/manager', '/control',
            '/admin_area', '/admin_login', '/admincp', '/admincontrol',
            '/admin/index.html', '/admin/login.html', '/admin/admin.html',
            '/admin_area/admin.html', '/admin_area/login.html',
            '/siteadmin/login.html', '/siteadmin/index.html',
            '/admin/account.html', '/admin/index.php', '/admin_area/index.php',
            '/bb-admin/', '/admin/login.php', '/admin_area/login.php',
            '/adminLogin/', '/admin/admin.php', '/admin_area/admin.php',
            '/admin/controlpanel.php', '/admin.php', '/admincp/index.asp',
            '/admincp/login.asp', '/admincp/index.html', '/webadmin.html',
            '/webadmin/index.html', '/webadmin/admin.html', '/webadmin/login.html',
            '/user.html', '/modelsearch/login.html', '/moderator.html',
            '/moderator/login.html', '/moderator/admin.html', '/account.html',
            '/controlpanel.html', '/admincontrol.html', '/panel-administracion/',
            '/webadmin.php', '/webadmin/', '/wp-login.php', '/adminLogin.html',
            '/admin/adminLogin.html', '/home.html', '/adminarea/', '/adminarea/admin.html',
            '/adminarea/login.html', '/panel-administracion/index.html',
            '/panel-administracion/admin.html', '/modelsearch/index.html',
            '/modelsearch/admin.html', '/admincontrol/login.html',
            '/adm/', '/adm.html', '/moderator/login.php', '/user.php',
            '/account.php', '/controlpanel.php', '/admincontrol.php',
            '/admin_login.html', '/panel-administracion/login.html',
            '/wp-login.php', '/adminLogin.php', '/admin/adminLogin.php',
            
            # API endpoints
            '/api', '/api/v1', '/api/v2', '/api/v3', '/graphql', '/rest', 
            '/api/users', '/api/admin', '/api/config', '/api/status', 
            '/api/health', '/api/swagger', '/swagger.json', '/openapi.json', 
            '/api-docs', '/api/docs', '/api/swagger-ui', '/api/graphql',
            '/api/user', '/api/login', '/api/register', '/api/auth',
            '/api/token', '/api/refresh', '/api/logout', '/api/profile',
            '/api/settings', '/api/upload', '/api/download', '/api/search',
            '/api/products', '/api/orders', '/api/customers', '/api/inventory',
            '/api/payments', '/api/invoices', '/api/reports', '/api/analytics',
            '/api/metrics', '/api/logs', '/api/events', '/api/notifications',
            '/api/messages', '/api/comments', '/api/posts', '/api/articles',
            '/api/categories', '/api/tags', '/api/media', '/api/files',
            '/api/documents', '/api/images', '/api/videos', '/api/audio',
            '/.well-known/openid-configuration', '/oauth/authorize', '/oauth/token',
            '/oauth/revoke', '/oauth/userinfo', '/saml/metadata', '/saml/login',
            '/saml/logout', '/saml/acs', '/oidc/authorize', '/oidc/token',
            
            # Config files
            '/.env', '/.env.local', '/.env.production', '/.env.development',
            '/.env.staging', '/.env.test', '/.env.example', '/.env.backup',
            '/config.php', '/config.json', '/settings.php', '/wp-config.php',
            '/database.yml', '/config.xml', '/web.config', '/app.config',
            '/.git/config', '/.svn/entries', '/.htaccess', '/.htpasswd',
            '/configuration.php', '/config.inc.php', '/settings.ini',
            '/parameters.yml', '/parameters.ini', '/database.php',
            '/db.php', '/database.ini', '/dbconfig.xml', '/db_config.php',
            '/application.yml', '/application.properties', '/bootstrap.yml',
            '/application.ini', '/settings.xml', '/config.yaml',
            '/serverless.yml', '/docker-compose.yml', '/ansible.cfg',
            '/terraform.tfvars', '/variables.tf', '/main.tf',
            
            # Backup files
            '/backup', '/backups', '/backup.sql', '/dump.sql', '/db.sql',
            '/backup.zip', '/backup.tar.gz', '/site.zip', '/www.zip',
            '/database.sql', '/mysql.sql', '/db_backup.sql', '/data.sql',
            '/backup.tar', '/backup.rar', '/backup.7z', '/backup.bak',
            '/site_backup.zip', '/website_backup.zip', '/public_html.zip',
            '/www.tar.gz', '/archive.zip', '/old.zip', '/files.zip',
            '/dump.tar.gz', '/database_backup.sql', '/db_dump.sql',
            '/backup_2024.zip', '/backup_2023.zip', '/daily_backup.zip',
            '/weekly_backup.zip', '/monthly_backup.zip', '/full_backup.zip',
            
            # Common paths
            '/robots.txt', '/sitemap.xml', '/crossdomain.xml', '/humans.txt',
            '/security.txt', '/.well-known/security.txt', '/readme.html',
            '/license.txt', '/changelog.txt', '/version.txt', '/info.php',
            '/phpinfo.php', '/test.php', '/index.php.bak', '/index.html.bak',
            '/README.md', '/CHANGELOG.md', '/TODO.md', '/INSTALL.md',
            '/CONTRIBUTING.md', '/AUTHORS', '/MAINTAINERS', '/SECURITY.md',
            '/favicon.ico', '/browserconfig.xml', '/manifest.json',
            '/service-worker.js', '/sw.js', '/.well-known/apple-app-site-association',
            '/.well-known/assetlinks.json', '/.well-known/host-meta',
            
            # Development files
            '/.git', '/.gitignore', '/.gitattributes', '/.gitmodules',
            '/.dockerignore', '/Dockerfile', '/docker-compose.yml',
            '/docker-compose.yaml', '/package.json', '/composer.json',
            '/requirements.txt', '/Gemfile', '/yarn.lock', '/package-lock.json',
            '/composer.lock', '/Pipfile', '/Pipfile.lock', '/poetry.lock',
            '/pom.xml', '/build.gradle', '/build.sbt', '/Makefile',
            '/webpack.config.js', '/gulpfile.js', '/Gruntfile.js',
            '/tsconfig.json', '/jsconfig.json', '/babel.config.js',
            '/.eslintrc', '/.prettierrc', '/.stylelintrc', '/.editorconfig',
            '/jest.config.js', '/karma.conf.js', '/protractor.conf.js',
            '/angular.json', '/vue.config.js', '/next.config.js',
            '/nuxt.config.js', '/gatsby-config.js', '/rollup.config.js',
            
            # Cloud/Container
            '/.aws/credentials', '/.aws/config', '/.kube/config', 
            '/kubernetes.yml', '/.docker/config.json', '/deployment.yaml', 
            '/service.yaml', '/ingress.yaml', '/configmap.yaml',
            '/secret.yaml', '/pod.yaml', '/statefulset.yaml',
            '/daemonset.yaml', '/job.yaml', '/cronjob.yaml',
            '/helm/values.yaml', '/helm/Chart.yaml', '/terraform.tfstate',
            '/terraform.tfstate.backup', '/.terraform/', '/ansible/',
            '/playbook.yml', '/inventory', '/group_vars/', '/host_vars/',
            
            # Sensitive directories
            '/uploads', '/upload', '/files', '/documents', '/private',
            '/confidential', '/secret', '/hidden', '/restricted', '/secure',
            '/internal', '/intranet', '/extranet', '/data', '/database',
            '/temp', '/tmp', '/cache', '/logs', '/log', '/backup',
            '/download', '/downloads', '/export', '/reports', '/invoices',
            '/contracts', '/agreements', '/proposals', '/quotes',
            '/customers', '/clients', '/users', '/members', '/employees',
            '/staff', '/personnel', '/payroll', '/finance', '/accounting',
            '/hr', '/human-resources', '/legal', '/compliance',
            
            # CMS specific
            '/wp-content', '/wp-includes', '/wp-json', '/xmlrpc.php',
            '/joomla', '/drupal', '/magento', '/prestashop', '/opencart',
            '/typo3', '/concrete5', '/modx', '/expressionengine',
            '/sites/default/files', '/administrator/components',
            '/media/com_', '/modules/', '/plugins/', '/themes/',
            '/templates/', '/components/', '/libraries/', '/includes/',
            '/app/etc/local.xml', '/var/log/', '/var/report/',
            '/downloader/', '/errors/local.xml', '/shell/',
            
            # Server status
            '/server-status', '/server-info', '/phpinfo.php', '/info',
            '/status', '/health', '/metrics', '/monitoring', '/debug',
            '/trace', '/ping', '/check', '/alive', '/ready',
            '/diagnostics', '/stats', '/statistics', '/analytics',
            '/_stats', '/_health', '/_metrics', '/_status',
            '/nginx_status', '/apache_status', '/php-fpm/status',
            
            # Authentication
            '/login', '/signin', '/auth', '/authenticate', '/oauth',
            '/saml', '/sso', '/register', '/signup', '/password',
            '/forgot-password', '/reset-password', '/change-password',
            '/profile', '/account', '/dashboard', '/user', '/users',
            '/logout', '/signout', '/lock', '/unlock', '/verify',
            '/confirm', '/activate', '/validation', '/2fa', '/mfa',
            
            # Keys and certificates
            '/private.key', '/public.key', '/cert.pem', '/ca.crt',
            '/.ssh/id_rsa', '/.ssh/id_rsa.pub', '/.ssh/authorized_keys',
            '/ssl/private.key', '/ssl/certificate.crt', '/id_rsa',
            '/id_dsa', '/id_ecdsa', '/id_ed25519', '/.ssh/known_hosts',
            '/server.key', '/server.crt', '/client.key', '/client.crt',
            '/root.crt', '/intermediate.crt', '/chain.pem', '/fullchain.pem',
            '/privkey.pem', '/cert.pfx', '/keystore.jks', '/truststore.jks'
        ]
        
        # Expanded CMS and technology signatures
        self.cms_signatures = {
            # CMS Platforms
            'WordPress': ['wp-content', 'wp-includes', 'wp-json', 'wp-admin', 'wordpress'],
            'Joomla': ['joomla', 'com_content', 'com_users', 'option=com_'],
            'Drupal': ['drupal', 'sites/default', 'modules', 'misc/drupal.js'],
            'Magento': ['magento', 'catalog/product', 'checkout/cart', 'skin/frontend'],
            'Shopify': ['shopify', 'cdn.shopify.com', 'myshopify.com'],
            'Wix': ['wix.com', 'static.wixstatic.com', 'parastorage.com'],
            'Squarespace': ['squarespace', 'static.squarespace.com', 'sqsp.net'],
            'PrestaShop': ['prestashop', 'modules/blockcart', 'img/prestashop'],
            'OpenCart': ['opencart', 'catalog/view/theme', 'index.php?route='],
            'TYPO3': ['typo3', 'typo3conf', 'typo3temp'],
            'Concrete5': ['concrete5', 'concrete/css', 'ccm/system'],
            'ModX': ['modx', 'assets/snippets', 'manager/'],
            'ExpressionEngine': ['expressionengine', 'exp:channel', 'system/ee'],
            'Ghost': ['ghost', 'ghost/api', 'content/themes'],
            'Contentful': ['contentful', 'ctfassets.net'],
            'Strapi': ['strapi', '_content', 'strapi/admin'],
            'Craft CMS': ['craftcms', 'cpresources', 'craft/config'],
            'Umbraco': ['umbraco', 'umbraco/surface', 'umbraco/api'],
            'Sitecore': ['sitecore', 'sitecore/admin', 'sitecore/shell'],
            'DNN': ['dotnetnuke', 'dnn', 'DesktopModules', 'Portals'],
            'Kentico': ['kentico', 'CMSPages', 'CMSModules'],
            'Liferay': ['liferay', 'liferay-portal', 'group/guest'],
            'HubSpot': ['hubspot', 'hs-scripts.com', 'hsforms.net'],
            'Adobe Experience Manager': ['aem', 'etc/designs', 'content/dam'],
            'Contentstack': ['contentstack', 'contentstack.io'],
            'Webflow': ['webflow', 'webflow.com', 'webflow.io'],
            'Gatsby': ['gatsby', 'gatsby-link', '__gatsby'],
            'Jekyll': ['jekyll', '_site', '_posts'],
            
            # JavaScript Frameworks
            'React': ['react', '__react', 'React.createElement', '_jsx', 'ReactDOM'],
            'Angular': ['ng-app', 'angular', 'ng-version', 'ng-controller', 'angular.module'],
            'Vue.js': ['vue', 'v-if', 'v-for', 'v-model', 'v-show', 'Vue.component'],
            'jQuery': ['jquery', 'jQuery', '$(document)', '$.ajax'],
            'Next.js': ['next', '__NEXT_DATA__', '_next/static', 'nextjs'],
            'Nuxt.js': ['nuxt', '__NUXT__', '_nuxt', 'nuxt.config'],
            'Svelte': ['svelte', '__svelte', 'svelte/internal'],
            'Ember.js': ['ember', 'Ember.Application', 'ember-cli'],
            'Backbone.js': ['backbone', 'Backbone.Model', 'Backbone.View'],
            'Alpine.js': ['alpine', 'x-data', 'x-show', 'Alpine.start'],
            'Meteor': ['meteor', 'Meteor.call', 'Meteor.startup'],
            'Aurelia': ['aurelia', 'aurelia-app', 'aurelia-bootstrapper'],
            'Polymer': ['polymer', 'polymer-element', 'web-components'],
            'Riot.js': ['riot', 'riot.mount', 'riot-tag'],
            'Mithril': ['mithril', 'm.render', 'm.component'],
            'Stimulus': ['stimulus', 'data-controller', 'stimulus.js'],
            'Lit': ['lit', 'lit-element', 'lit-html'],
            'Preact': ['preact', 'preact/compat', 'h('],
            'Solid.js': ['solid', 'createSignal', 'createEffect'],
            'Qwik': ['qwik', 'qwik/core', 'useSignal'],
            'Astro': ['astro', 'astro:content', 'astro-island'],
            
            # Backend Frameworks
            'Django': ['django', '__debug__', 'csrfmiddlewaretoken'],
            'Flask': ['flask', 'werkzeug', 'jinja2'],
            'FastAPI': ['fastapi', 'starlette', 'pydantic'],
            'Laravel': ['laravel', 'telescope', 'laravel_session'],
            'Symfony': ['symfony', 'sf-toolbar', '_profiler'],
            'CodeIgniter': ['codeigniter', 'ci_session', 'system/core'],
            'Ruby on Rails': ['rails', 'action_controller', 'rails/info'],
            'Express.js': ['express', 'x-powered-by: Express'],
            'Spring': ['spring', 'spring-boot', 'spring-security'],
            'ASP.NET': ['asp.net', '__viewstate', '__eventvalidation'],
            'Phoenix': ['phoenix', 'phoenix_html', 'phoenix.js'],
            'Gin': ['gin-gonic', 'gin.context'],
            'Echo': ['echo', 'labstack/echo'],
            'Fiber': ['gofiber', 'fiber.ctx'],
            'Koa': ['koa', 'koa-router', 'koa-static'],
            'Hapi': ['hapi', '@hapi/hapi', 'hapijs'],
            'Fastify': ['fastify', 'fastify-plugin'],
            'NestJS': ['nestjs', '@nestjs/core', 'nest-module'],
            'AdonisJS': ['adonisjs', '@adonisjs/core'],
            'Sails.js': ['sails', 'sails.js', 'sailsjs'],
            'Struts': ['struts', 'struts2', '.action'],
            'Play Framework': ['playframework', 'play.mvc'],
            'Grails': ['grails', 'grails-app', 'gsp'],
            'Vaadin': ['vaadin', 'vaadin-', 'v-slot'],
            'Wicket': ['wicket', 'wicket:id', 'wicket-'],
            
            # Databases
            'MongoDB': ['mongodb', 'mongoose', 'mongo'],
            'PostgreSQL': ['postgresql', 'postgres', 'pg_'],
            'MySQL': ['mysql', 'mysqli', 'phpmyadmin'],
            'MariaDB': ['mariadb', 'maria'],
            'Redis': ['redis', 'redis-cli', 'ioredis'],
            'Elasticsearch': ['elasticsearch', 'elastic', '_search'],
            'Cassandra': ['cassandra', 'cql', 'datastax'],
            'CouchDB': ['couchdb', '_couch', 'futon'],
            'Neo4j': ['neo4j', 'cypher', 'graphdb'],
            'SQLite': ['sqlite', 'sqlite3', '.db'],
            'Oracle': ['oracle', 'oci', 'tnsnames'],
            'SQL Server': ['sqlserver', 'mssql', 'tsql'],
            'DynamoDB': ['dynamodb', 'aws-sdk-dynamodb'],
            'Firebase': ['firebase', 'firestore', 'firebaseapp.com'],
            'Supabase': ['supabase', 'supabase.io', 'supabase.co'],
            
            # Cloud Providers
            'AWS': ['amazonaws.com', 'aws-sdk', 's3.amazonaws', 'cloudfront.net'],
            'Google Cloud': ['googleapis.com', 'googleusercontent.com', 'gcp', 'appspot.com'],
            'Azure': ['azure', 'windows.net', 'azurewebsites.net', 'blob.core.windows.net'],
            'Cloudflare': ['cloudflare', 'cf-', 'cloudflare.com'],
            'DigitalOcean': ['digitalocean', 'digitaloceanspaces.com', 'do-spaces'],
            'Heroku': ['heroku', 'herokuapp.com', 'herokucdn.com'],
            'Vercel': ['vercel', 'vercel.app', 'now.sh'],
            'Netlify': ['netlify', 'netlify.app', 'netlify.com'],
            'Alibaba Cloud': ['aliyun', 'alibabacloud', 'aliyuncs.com'],
            'IBM Cloud': ['ibm.com', 'bluemix', 'watson'],
            'Oracle Cloud': ['oraclecloud', 'ocp.oraclecloud.com'],
            
            # DevOps Tools
            'Docker': ['docker', 'dockerfile', 'docker-compose'],
            'Kubernetes': ['kubernetes', 'k8s', 'kubectl'],
            'Jenkins': ['jenkins', 'hudson', 'jenkins-ci'],
            'GitLab': ['gitlab', 'gitlab-ci', '.gitlab-ci.yml'],
            'GitHub': ['github', 'github.com', 'githubusercontent.com'],
            'Bitbucket': ['bitbucket', 'atlassian', 'bitbucket.org'],
            'CircleCI': ['circleci', 'circle.yml', '.circleci'],
            'TravisCI': ['travis-ci', '.travis.yml', 'travis'],
            'Ansible': ['ansible', 'playbook', 'ansible-galaxy'],
            'Terraform': ['terraform', 'hashicorp', '.tf'],
            'Puppet': ['puppet', 'puppetlabs', 'puppet.conf'],
            'Chef': ['chef', 'chef.io', 'cookbooks'],
            
            # Analytics & Monitoring
            'Google Analytics': ['google-analytics', 'ga.js', 'gtag', 'analytics.js'],
            'Google Tag Manager': ['googletagmanager', 'gtm.js', 'GTM-'],
            'Matomo': ['matomo', 'piwik', 'matomo.js'],
            'Hotjar': ['hotjar', 'hotjar.com', 'hj('],
            'Mixpanel': ['mixpanel', 'mixpanel.com', 'mixpanel.track'],
            'Segment': ['segment', 'segment.io', 'analytics.track'],
            'New Relic': ['newrelic', 'nr-data.net', 'newrelic.com'],
            'Datadog': ['datadog', 'datadoghq', 'dd-trace'],
            'Sentry': ['sentry', 'sentry.io', 'raven.js'],
            'Rollbar': ['rollbar', 'rollbar.com', 'rollbar.js'],
            'LogRocket': ['logrocket', 'logrocket.com', 'LogRocket.init'],
            'FullStory': ['fullstory', 'fullstory.com', 'FS.identify']
        }

    def show_banner(self):
        """Display tool banner"""
        banner = f"""
{Colors.OKCYAN}
==================================================================
||                                                              ||
||  ##      ## ######## ########   ######  ########  ########  ||
||  ##  ##  ## ##       ##     ## ##       ##     ## ##       ||
||  ##  ##  ## ##       ##     ##  ######  ########  ######   ||
||  ##  ##  ## ######   ########        ## ##        ##       ||
||  ##  ##  ## ##       ##     ## ##    ## ##        ##       ||
||   ###  ###  ######## ########   ######  ##        ########  ||
||                                                              ||
||          Advanced Web Information Gathering Tool            ||
||                    [Recon Framework]                        ||
==================================================================
{Colors.ENDC}
        """
        print(banner)

    def loading_animation(self, task_name, duration=2):
        """Display hacker-themed loading animation"""
        frames = ['[/]', '[-]', '[\\]', '[|]', '[/]', '[-]', '[\\]', '[|]']
        end_time = time.time() + duration
        i = 0
        while time.time() < end_time:
            sys.stdout.write(f'\r{Colors.OKGREEN}{frames[i % len(frames)]} {task_name}...{Colors.ENDC}')
            sys.stdout.flush()
            time.sleep(0.1)
            i += 1
        sys.stdout.write(f'\r{Colors.OKGREEN}[+] {task_name} completed!{Colors.ENDC}\n')

    def check_security_headers(self):
        """Analyze security headers"""
        print(f"\n{Colors.OKCYAN}[*] Analyzing Security Headers...{Colors.ENDC}")
        security_headers = [
            'Strict-Transport-Security',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Content-Security-Policy',
            'X-XSS-Protection',
            'Referrer-Policy',
            'Feature-Policy',
            'Permissions-Policy',
            'X-Permitted-Cross-Domain-Policies',
            'X-Download-Options',
            'X-Content-Duration',
            'Expect-CT',
            'Cross-Origin-Embedder-Policy',
            'Cross-Origin-Opener-Policy',
            'Cross-Origin-Resource-Policy',
            'Cache-Control',
            'Pragma',
            'Expires',
            'X-Robots-Tag',
            'X-UA-Compatible'
        ]
        
        try:
            response = self.session.get(self.target_url, verify=False, timeout=10)
            for header in security_headers:
                if header in response.headers:
                    self.results['security_headers'][header] = response.headers[header]
                    print(f"  {Colors.OKGREEN}[+]{Colors.ENDC} {header}: {response.headers[header][:50]}...")
                else:
                    self.results['security_headers'][header] = "Not Set"
                    print(f"  {Colors.WARNING}[-]{Colors.ENDC} {header}: Not Set")
        except Exception as e:
            print(f"  {Colors.FAIL}[!] Error: {str(e)}{Colors.ENDC}")

    def check_ssl_certificate(self):
        """Inspect SSL certificate"""
        print(f"\n{Colors.OKCYAN}[*] Inspecting SSL Certificate...{Colors.ENDC}")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    self.results['ssl_info'] = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter']
                    }
                    print(f"  {Colors.OKGREEN}[+]{Colors.ENDC} Issuer: {self.results['ssl_info']['issuer'].get('organizationName', 'N/A')}")
                    print(f"  {Colors.OKGREEN}[+]{Colors.ENDC} Valid Until: {cert['notAfter']}")
        except Exception as e:
            self.results['ssl_info']['error'] = str(e)
            print(f"  {Colors.FAIL}[!] Error: {str(e)}{Colors.ENDC}")

    def get_whois_info(self):
        """Get WHOIS domain information"""
        print(f"\n{Colors.OKCYAN}[*] Fetching WHOIS Information...{Colors.ENDC}")
        try:
            w = whois.whois(self.domain)
            self.results['whois_info'] = {
                'registrar': w.registrar if hasattr(w, 'registrar') else 'N/A',
                'creation_date': str(w.creation_date) if hasattr(w, 'creation_date') else 'N/A',
                'expiration_date': str(w.expiration_date) if hasattr(w, 'expiration_date') else 'N/A',
                'name_servers': w.name_servers if hasattr(w, 'name_servers') else [],
                'emails': w.emails if hasattr(w, 'emails') else []
            }
            print(f"  {Colors.OKGREEN}[+]{Colors.ENDC} Registrar: {self.results['whois_info']['registrar']}")
            print(f"  {Colors.OKGREEN}[+]{Colors.ENDC} Created: {self.results['whois_info']['creation_date']}")
        except Exception as e:
            self.results['whois_info']['error'] = str(e)
            print(f"  {Colors.FAIL}[!] Error: {str(e)}{Colors.ENDC}")

    def discover_paths(self):
        """Discover common paths and endpoints"""
        print(f"\n{Colors.OKCYAN}[*] Discovering Paths & Endpoints...{Colors.ENDC}")
        discovered = []
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = []
            for path in self.path_wordlist:
                url = urljoin(self.target_url, path)
                futures.append(executor.submit(self.check_path, url))
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    discovered.append(result)
                    print(f"  {Colors.OKGREEN}[+]{Colors.ENDC} Found: {result['path']} [{result['status']}]")
        
        self.results['discovered_paths'] = discovered

    def check_path(self, url):
        """Check if a path exists"""
        try:
            response = self.session.head(url, verify=False, timeout=3, allow_redirects=False)
            if response.status_code in [200, 201, 301, 302, 401, 403]:
                return {
                    'path': urlparse(url).path,
                    'status': response.status_code,
                    'size': response.headers.get('Content-Length', 'N/A')
                }
        except:
            pass
        return None

    def detect_technologies(self):
        """Detect CMS, frameworks, and technologies"""
        print(f"\n{Colors.OKCYAN}[*] Detecting Technologies & CMS...{Colors.ENDC}")
        try:
            response = self.session.get(self.target_url, verify=False, timeout=10)
            content = response.text.lower()
            headers = response.headers
            
            # Check for CMS and technologies
            detected_count = 0
            for tech_category, signatures in self.cms_signatures.items():
                for signature in signatures:
                    if signature.lower() in content or signature.lower() in str(headers).lower():
                        self.results['cms_detection'][tech_category] = True
                        print(f"  {Colors.OKGREEN}[+]{Colors.ENDC} Detected: {tech_category}")
                        detected_count += 1
                        break
            
            # Check headers for technologies
            tech_headers = {
                'X-Powered-By': headers.get('X-Powered-By', ''),
                'Server': headers.get('Server', ''),
                'X-AspNet-Version': headers.get('X-AspNet-Version', ''),
                'X-Generator': headers.get('X-Generator', ''),
                'X-Drupal-Cache': headers.get('X-Drupal-Cache', ''),
                'X-Drupal-Dynamic-Cache': headers.get('X-Drupal-Dynamic-Cache', ''),
                'X-Varnish': headers.get('X-Varnish', ''),
                'Via': headers.get('Via', ''),
                'X-Served-By': headers.get('X-Served-By', ''),
                'X-Cache': headers.get('X-Cache', ''),
                'X-Cache-Hits': headers.get('X-Cache-Hits', ''),
                'X-Timer': headers.get('X-Timer', ''),
                'X-Runtime': headers.get('X-Runtime', ''),
                'X-Version': headers.get('X-Version', ''),
                'X-Backend-Server': headers.get('X-Backend-Server', '')
            }
            
            for header, value in tech_headers.items():
                if value:
                    self.results['technologies'][header] = value
                    print(f"  {Colors.OKGREEN}[+]{Colors.ENDC} {header}: {value}")
                    detected_count += 1
            
            # Additional technology detection patterns
            tech_patterns = {
                'PHP': ['<?php', '.php', 'phpsessid'],
                'ASP.NET': ['__viewstate', '__eventvalidation', '.aspx', 'asp.net'],
                'Java': ['.jsp', '.do', 'jsessionid', 'java/'],
                'Python': ['wsgi', 'python/', 'django', 'flask'],
                'Ruby': ['ruby/', 'rails', 'rack', 'passenger'],
                'Node.js': ['node/', 'express', 'x-powered-by: express'],
                'Perl': ['.pl', 'perl/', 'cgi-bin'],
                'Go': ['go/', 'golang', 'gin-gonic'],
                'Rust': ['rust/', 'actix', 'rocket'],
                'Nginx': ['nginx', 'nginx/'],
                'Apache': ['apache', 'httpd', 'mod_'],
                'IIS': ['iis', 'microsoft-iis', 'asp.net'],
                'Tomcat': ['tomcat', 'coyote', 'servlet'],
                'WebLogic': ['weblogic', 'wls', 'oracle'],
                'WebSphere': ['websphere', 'ibm', 'was'],
                'Jetty': ['jetty', 'eclipse'],
                'Caddy': ['caddy', 'caddy/'],
                'LiteSpeed': ['litespeed', 'lsws']
            }
            
            for tech, patterns in tech_patterns.items():
                for pattern in patterns:
                    if pattern in content or pattern in str(headers).lower():
                        if tech not in self.results['technologies']:
                            self.results['technologies'][tech] = True
                            print(f"  {Colors.OKGREEN}[+]{Colors.ENDC} Technology: {tech}")
                            detected_count += 1
                        break
            
            if detected_count == 0:
                print(f"  {Colors.WARNING}[-]{Colors.ENDC} No specific technologies detected")
                        
        except Exception as e:
            print(f"  {Colors.FAIL}[!] Error: {str(e)}{Colors.ENDC}")

    def get_dns_records(self):
        """Get DNS records"""
        print(f"\n{Colors.OKCYAN}[*] Fetching DNS Records...{Colors.ENDC}")
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR', 'SRV', 'CAA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                self.results['dns_records'][record_type] = []
                for rdata in answers:
                    record_value = str(rdata)
                    self.results['dns_records'][record_type].append(record_value)
                    print(f"  {Colors.OKGREEN}[+]{Colors.ENDC} {record_type}: {record_value[:50]}...")
            except:
                pass

    def extract_urls(self):
        """Extract all URLs from the website"""
        print(f"\n{Colors.OKCYAN}[*] Extracting URLs...{Colors.ENDC}")
        try:
            response = self.session.get(self.target_url, verify=False, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            urls = set()
            # Extract from various tags
            for tag in soup.find_all(['a', 'link', 'script', 'img', 'iframe', 'embed', 'source', 'video', 'audio']):
                url = tag.get('href') or tag.get('src') or tag.get('data-src') or tag.get('action')
                if url:
                    urls.add(url)
            
            # Extract from inline styles
            for tag in soup.find_all(style=True):
                style = tag['style']
                url_pattern = r'url\(["\']?([^"\'()]+)["\']?\)'
                found_urls = re.findall(url_pattern, style)
                urls.update(found_urls)
            
            self.results['urls'] = list(urls)[:100]  # Limit to 100 URLs
            print(f"  {Colors.OKGREEN}[+]{Colors.ENDC} Found {len(urls)} URLs")
            
            # Identify third-party resources
            third_party = []
            for url in urls:
                if url.startswith('http') and self.domain not in url:
                    parsed = urlparse(url)
                    if parsed.netloc and parsed.netloc not in third_party:
                        third_party.append(parsed.netloc)
            
            self.results['third_party'] = third_party[:30]  # Limit to 30
            if third_party:
                print(f"  {Colors.OKGREEN}[+]{Colors.ENDC} Third-party domains: {', '.join(third_party[:5])}...")
                
        except Exception as e:
            print(f"  {Colors.FAIL}[!] Error: {str(e)}{Colors.ENDC}")

    def analyze_javascript(self):
        """Analyze JavaScript and client-side storage"""
        print(f"\n{Colors.OKCYAN}[*] Analyzing JavaScript & Client Storage...{Colors.ENDC}")
        try:
            response = self.session.get(self.target_url, verify=False, timeout=10)
            content = response.text
            
            # Look for localStorage/sessionStorage usage
            storage_patterns = [
                r'localStorage\.',
                r'sessionStorage\.',
                r'document\.cookie',
                r'indexedDB\.',
                r'caches\.',
                r'webkitRequestFileSystem',
                r'requestFileSystem',
                r'openDatabase\('
            ]
            
            storage_found = []
            for pattern in storage_patterns:
                if re.search(pattern, content):
                    storage_type = pattern.replace('\\', '').replace('.', '').replace('(', '')
                    storage_found.append(storage_type)
                    print(f"  {Colors.OKGREEN}[+]{Colors.ENDC} Found: {storage_type} usage")
            
            self.results['js_analysis']['storage'] = storage_found
            
            # Look for API keys or sensitive data
            api_patterns = [
                r'["\']api[_-]?key["\']\s*:\s*["\']([^"\']+)["\']',
                r'["\']apiKey["\']\s*:\s*["\']([^"\']+)["\']',
                r'["\']token["\']\s*:\s*["\']([^"\']+)["\']',
                r'["\']secret["\']\s*:\s*["\']([^"\']+)["\']',
                r'["\']password["\']\s*:\s*["\']([^"\']+)["\']',
                r'["\']auth["\']\s*:\s*["\']([^"\']+)["\']',
                r'["\']authorization["\']\s*:\s*["\']([^"\']+)["\']',
                r'["\']access[_-]?token["\']\s*:\s*["\']([^"\']+)["\']',
                r'["\']client[_-]?id["\']\s*:\s*["\']([^"\']+)["\']',
                r'["\']client[_-]?secret["\']\s*:\s*["\']([^"\']+)["\']',
                r'AIza[0-9A-Za-z\-_]{35}',  # Google API Key
                r'sk_live_[0-9a-zA-Z]{24}',  # Stripe Live Key
                r'pk_live_[0-9a-zA-Z]{24}',  # Stripe Publishable Key
                r'[0-9a-f]{32}-us[0-9]{1,2}',  # Mailchimp API Key
                r'key-[0-9a-zA-Z]{32}',  # Mailgun API Key
                r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'  # UUID
            ]
            
            potential_keys = []
            for pattern in api_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    potential_keys.extend(matches[:5])  # Limit matches
            
            if potential_keys:
                self.results['js_analysis']['potential_keys'] = len(potential_keys)
                print(f"  {Colors.WARNING}[!]{Colors.ENDC} Found {len(potential_keys)} potential API keys/tokens")
            
            # Check for exposed endpoints in JavaScript
            endpoint_patterns = [
                r'["\']\/api\/[^"\']*["\']',
                r'["\']https?:\/\/[^"\']*\/api[^"\']*["\']',
                r'fetch\(["\']([^"\']+)["\']\)',
                r'axios\.[get|post|put|delete]\(["\']([^"\']+)["\']\)',
                r'\$\.ajax\({[^}]*url:\s*["\']([^"\']+)["\']'
            ]
            
            endpoints = []
            for pattern in endpoint_patterns:
                matches = re.findall(pattern, content)
                endpoints.extend(matches[:10])
            
            if endpoints:
                self.results['js_analysis']['endpoints'] = list(set(endpoints))[:20]
                print(f"  {Colors.OKGREEN}[+]{Colors.ENDC} Found {len(set(endpoints))} API endpoints")
                
        except Exception as e:
            print(f"  {Colors.FAIL}[!] Error: {str(e)}{Colors.ENDC}")

    def extract_metadata(self):
        """Extract metadata from the website"""
        print(f"\n{Colors.OKCYAN}[*] Extracting Metadata...{Colors.ENDC}")
        try:
            response = self.session.get(self.target_url, verify=False, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract meta tags
            meta_tags = {}
            for tag in soup.find_all('meta'):
                name = tag.get('name') or tag.get('property') or tag.get('http-equiv')
                content = tag.get('content')
                if name and content:
                    meta_tags[name] = content[:200]  # Limit content length
            
            self.results['metadata']['meta_tags'] = meta_tags
            
            # Extract title
            title = soup.find('title')
            if title:
                self.results['metadata']['title'] = title.text
                print(f"  {Colors.OKGREEN}[+]{Colors.ENDC} Title: {title.text[:50]}...")
            
            # Extract generator
            generator = soup.find('meta', {'name': 'generator'})
            if generator:
                self.results['metadata']['generator'] = generator.get('content')
                print(f"  {Colors.OKGREEN}[+]{Colors.ENDC} Generator: {generator.get('content')}")
            
            # Extract author
            author = soup.find('meta', {'name': 'author'})
            if author:
                self.results['metadata']['author'] = author.get('content')
                print(f"  {Colors.OKGREEN}[+]{Colors.ENDC} Author: {author.get('content')}")
            
            # Extract description
            description = soup.find('meta', {'name': 'description'})
            if description:
                self.results['metadata']['description'] = description.get('content')
                print(f"  {Colors.OKGREEN}[+]{Colors.ENDC} Description: {description.get('content')[:50]}...")
                
            print(f"  {Colors.OKGREEN}[+]{Colors.ENDC} Found {len(meta_tags)} meta tags")
            
        except Exception as e:
            print(f"  {Colors.FAIL}[!] Error: {str(e)}{Colors.ENDC}")

    def generate_html_report(self):
        """Generate HTML report"""
        print(f"\n{Colors.OKCYAN}[*] Generating HTML Report...{Colors.ENDC}")
        
        html_content = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebSpec Report - ''' + self.domain + '''</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Courier New', monospace;
            background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 100%);
            color: #00ff41;
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .header {
            text-align: center;
            padding: 40px 0;
            border-bottom: 2px solid #00ff41;
            margin-bottom: 40px;
            position: relative;
        }
        
        .header::before {
            content: "";
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: linear-gradient(90deg, transparent, #00ff41, transparent);
            animation: scan 2s linear infinite;
        }
        
        @keyframes scan {
            0% { transform: translateX(-100%); }
            100% { transform: translateX(100%); }
        }
        
        h1 {
            font-size: 48px;
            text-transform: uppercase;
            letter-spacing: 4px;
            margin-bottom: 10px;
            text-shadow: 0 0 20px #00ff41;
        }
        
        .subtitle {
            color: #888;
            font-size: 14px;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        
        .info-card {
            background: rgba(0, 255, 65, 0.05);
            border: 1px solid #00ff41;
            border-radius: 8px;
            padding: 20px;
            position: relative;
            overflow: hidden;
        }
        
        .info-card::before {
            content: "";
            position: absolute;
            top: -2px;
            left: -2px;
            right: -2px;
            bottom: -2px;
            background: linear-gradient(45deg, #00ff41, transparent, #00ff41);
            opacity: 0;
            animation: glow 3s ease-in-out infinite;
            z-index: -1;
        }
        
        .info-card:hover::before {
            opacity: 0.3;
        }
        
        .card-title {
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 15px;
            text-transform: uppercase;
            border-bottom: 1px solid rgba(0, 255, 65, 0.3);
            padding-bottom: 10px;
        }
        
        .card-content {
            font-size: 14px;
            line-height: 1.6;
        }
        
        .status-ok {
            color: #00ff41;
        }
        
        .status-warning {
            color: #ffaa00;
        }
        
        .status-error {
            color: #ff3333;
        }
        
        .data-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }
        
        .data-table td {
            padding: 8px;
            border-bottom: 1px solid rgba(0, 255, 65, 0.2);
            font-size: 13px;
        }
        
        .data-table td:first-child {
            font-weight: bold;
            color: #00ff41;
            width: 40%;
        }
        
        .data-table td:last-child {
            color: #aaa;
            word-break: break-all;
        }
        
        .path-list {
            max-height: 300px;
            overflow-y: auto;
            margin-top: 10px;
        }
        
        .path-item {
            padding: 5px;
            margin: 2px 0;
            background: rgba(0, 255, 65, 0.1);
            border-left: 2px solid #00ff41;
            font-size: 13px;
        }
        
        .footer {
            text-align: center;
            margin-top: 60px;
            padding: 20px;
            border-top: 1px solid rgba(0, 255, 65, 0.3);
            color: #666;
        }
        
        .tech-badge {
            display: inline-block;
            padding: 4px 12px;
            margin: 4px;
            background: rgba(0, 255, 65, 0.2);
            border: 1px solid #00ff41;
            border-radius: 4px;
            font-size: 12px;
        }
        
        ::-webkit-scrollbar {
            width: 8px;
        }
        
        ::-webkit-scrollbar-track {
            background: #0a0a0a;
        }
        
        ::-webkit-scrollbar-thumb {
            background: #00ff41;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>WebSpec Report</h1>
            <div class="subtitle">Target: ''' + self.target_url + '''</div>
            <div class="subtitle">Scan Date: ''' + self.results['timestamp'] + '''</div>
        </div>
        
        <div class="info-grid">
            <!-- Security Headers -->
            <div class="info-card">
                <div class="card-title">[SECURITY HEADERS]</div>
                <div class="card-content">
                    <table class="data-table">'''
        
        # Add security headers
        for header, value in self.results['security_headers'].items():
            status_class = 'status-ok' if value != "Not Set" else 'status-warning'
            html_content += f'''
                        <tr>
                            <td>{header}</td>
                            <td class="{status_class}">{str(value)[:50]}...</td>
                        </tr>'''
        
        html_content += '''
                    </table>
                </div>
            </div>
            
            <!-- SSL Certificate -->
            <div class="info-card">
                <div class="card-title">[SSL CERTIFICATE]</div>
                <div class="card-content">
                    <table class="data-table">'''
        
        # Add SSL info
        if 'error' not in self.results['ssl_info']:
            if 'issuer' in self.results['ssl_info']:
                html_content += f'''
                        <tr>
                            <td>Issuer</td>
                            <td>{self.results['ssl_info']['issuer'].get('organizationName', 'N/A')}</td>
                        </tr>
                        <tr>
                            <td>Valid Until</td>
                            <td>{self.results['ssl_info'].get('not_after', 'N/A')}</td>
                        </tr>'''
        else:
            html_content += '''
                        <tr>
                            <td>Status</td>
                            <td class="status-error">Error retrieving certificate</td>
                        </tr>'''
        
        html_content += '''
                    </table>
                </div>
            </div>
            
            <!-- WHOIS Information -->
            <div class="info-card">
                <div class="card-title">[WHOIS INFORMATION]</div>
                <div class="card-content">
                    <table class="data-table">'''
        
        # Add WHOIS info
        if 'error' not in self.results['whois_info']:
            whois_data = self.results['whois_info']
            html_content += f'''
                        <tr>
                            <td>Registrar</td>
                            <td>{whois_data.get('registrar', 'N/A')}</td>
                        </tr>
                        <tr>
                            <td>Created</td>
                            <td>{whois_data.get('creation_date', 'N/A')}</td>
                        </tr>
                        <tr>
                            <td>Expires</td>
                            <td>{whois_data.get('expiration_date', 'N/A')}</td>
                        </tr>'''
        
        html_content += '''
                    </table>
                </div>
            </div>
            
            <!-- Technologies Detected -->
            <div class="info-card">
                <div class="card-title">[TECHNOLOGIES & CMS]</div>
                <div class="card-content">'''
        
        # Add detected technologies
        if self.results['cms_detection']:
            for cms in self.results['cms_detection']:
                html_content += f'<span class="tech-badge">{cms}</span>'
        
        if self.results['technologies']:
            for tech, value in self.results['technologies'].items():
                if isinstance(value, bool):
                    html_content += f'<span class="tech-badge">{tech}</span>'
                else:
                    html_content += f'<span class="tech-badge">{tech}: {str(value)[:30]}</span>'
        
        if not self.results['cms_detection'] and not self.results['technologies']:
            html_content += '<p class="status-warning">No specific technologies detected</p>'
        
        html_content += '''
                </div>
            </div>
            
            <!-- Discovered Paths -->
            <div class="info-card">
                <div class="card-title">[DISCOVERED PATHS]</div>
                <div class="card-content">
                    <div class="path-list">'''
        
        # Add discovered paths
        if self.results['discovered_paths']:
            for path_info in self.results['discovered_paths'][:30]:
                status_color = 'status-ok' if path_info['status'] == 200 else 'status-warning'
                html_content += f'''
                        <div class="path-item">
                            <span class="{status_color}">[{path_info['status']}]</span> {path_info['path']}
                        </div>'''
        else:
            html_content += '<p class="status-warning">No paths discovered</p>'
        
        html_content += '''
                    </div>
                </div>
            </div>
            
            <!-- DNS Records -->
            <div class="info-card">
                <div class="card-title">[DNS RECORDS]</div>
                <div class="card-content">
                    <table class="data-table">'''
        
        # Add DNS records
        if self.results['dns_records']:
            for record_type, records in self.results['dns_records'].items():
                if records:
                    html_content += f'''
                        <tr>
                            <td>{record_type}</td>
                            <td>{', '.join(str(r)[:50] for r in records[:3])}...</td>
                        </tr>'''
        else:
            html_content += '''
                        <tr>
                            <td>Status</td>
                            <td class="status-warning">No DNS records found</td>
                        </tr>'''
        
        html_content += '''
                    </table>
                </div>
            </div>
            
            <!-- JavaScript Analysis -->
            <div class="info-card">
                <div class="card-title">[JAVASCRIPT ANALYSIS]</div>
                <div class="card-content">'''
        
        # Add JS analysis
        if self.results['js_analysis'].get('storage'):
            html_content += "<p><strong>Client Storage Methods:</strong></p>"
            for storage in self.results['js_analysis']['storage']:
                html_content += f'<span class="tech-badge">{storage}</span>'
        
        if self.results['js_analysis'].get('potential_keys'):
            html_content += f'<p class="status-warning">[!] Found {self.results["js_analysis"]["potential_keys"]} potential API keys/tokens</p>'
        
        if self.results['js_analysis'].get('endpoints'):
            html_content += f'<p><strong>API Endpoints Found: {len(self.results["js_analysis"]["endpoints"])}</strong></p>'
        
        if not self.results['js_analysis']:
            html_content += '<p class="status-warning">No JavaScript analysis data</p>'
        
        html_content += '''
                </div>
            </div>
            
            <!-- Third-Party Resources -->
            <div class="info-card">
                <div class="card-title">[THIRD-PARTY DOMAINS]</div>
                <div class="card-content">
                    <div class="path-list">'''
        
        # Add third-party domains
        if self.results['third_party']:
            for domain in self.results['third_party'][:20]:
                html_content += f'''
                        <div class="path-item">{domain}</div>'''
        else:
            html_content += '<p class="status-warning">No third-party domains found</p>'
        
        html_content += '''
                    </div>
                </div>
            </div>
            
            <!-- Metadata -->
            <div class="info-card">
                <div class="card-title">[METADATA]</div>
                <div class="card-content">
                    <table class="data-table">'''
        
        # Add metadata
        if self.results['metadata'].get('title'):
            html_content += f'''
                        <tr>
                            <td>Title</td>
                            <td>{self.results['metadata']['title'][:100]}</td>
                        </tr>'''
        
        if self.results['metadata'].get('generator'):
            html_content += f'''
                        <tr>
                            <td>Generator</td>
                            <td>{self.results['metadata']['generator']}</td>
                        </tr>'''
        
        if self.results['metadata'].get('author'):
            html_content += f'''
                        <tr>
                            <td>Author</td>
                            <td>{self.results['metadata']['author']}</td>
                        </tr>'''
        
        if self.results['metadata'].get('description'):
            html_content += f'''
                        <tr>
                            <td>Description</td>
                            <td>{self.results['metadata']['description'][:100]}...</td>
                        </tr>'''
        
        if self.results['metadata'].get('meta_tags'):
            html_content += f'''
                        <tr>
                            <td>Meta Tags Count</td>
                            <td>{len(self.results['metadata']['meta_tags'])}</td>
                        </tr>'''
        
        if not self.results['metadata']:
            html_content += '''
                        <tr>
                            <td>Status</td>
                            <td class="status-warning">No metadata found</td>
                        </tr>'''
        
        html_content += '''
                    </table>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>WebSpec - Advanced Web Information Gathering Tool</p>
            <p style="color: #444;">Report generated at ''' + self.results['timestamp'] + '''</p>
        </div>
    </div>
</body>
</html>'''
        
        # Save the report
        filename = f"webspec_report_{self.domain.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            print(f"{Colors.OKGREEN}[+] Report saved as: {filename}{Colors.ENDC}")
            
            # Try to open the report in browser
            try:
                if platform.system() == 'Darwin':  # macOS
                    subprocess.call(['open', filename])
                elif platform.system() == 'Windows':  # Windows
                    os.startfile(filename)
                else:  # Linux
                    subprocess.call(['xdg-open', filename])
            except:
                pass
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error saving report: {str(e)}{Colors.ENDC}")

    def run_scan(self):
        """Run the complete scan"""
        self.show_banner()
        print(f"\n{Colors.BOLD}Target: {self.target_url}{Colors.ENDC}")
        print(f"{Colors.BOLD}Starting reconnaissance scan...{Colors.ENDC}\n")
        
        # Show initial loading animation
        self.loading_animation("Initializing scan modules", 2)
        
        # Run all scan modules
        scan_modules = [
            (self.check_security_headers, "Security Headers Analysis"),
            (self.check_ssl_certificate, "SSL Certificate Inspection"),
            (self.get_whois_info, "WHOIS Domain Information"),
            (self.discover_paths, "Path Discovery"),
            (self.detect_technologies, "Technology Detection"),
            (self.get_dns_records, "DNS Records"),
            (self.extract_urls, "URL Extraction"),
            (self.analyze_javascript, "JavaScript Analysis"),
            (self.extract_metadata, "Metadata Extraction")
        ]
        
        for module, name in scan_modules:
            try:
                module()
            except Exception as e:
                print(f"{Colors.FAIL}[!] Error in {name}: {str(e)}{Colors.ENDC}")
        
        # Generate report
        self.loading_animation("Generating report", 2)
        self.generate_html_report()
        
        print(f"\n{Colors.OKGREEN}{'='*60}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Scan completed successfully!{Colors.ENDC}")
        print(f"{Colors.OKGREEN}{'='*60}{Colors.ENDC}")

def main():
    """Main function"""
    try:
        # Clear screen
        os.system('cls' if os.name == 'nt' else 'clear')
        
        # ASCII art intro
        print(f"""{Colors.OKCYAN}
        ============================================================
        ||  WebSpec - Advanced Web Reconnaissance Tool           ||
        ||  Version 1.0 | Security Research Framework            ||
        ||  Author: Monish Kanna                                 ||
        ||  GitHub: https://github.com/TENETx0/web-Specter/      ||
        ||  Made with love from Monish Kanna                     ||
        ============================================================
        {Colors.ENDC}""")
        
        # Get target URL
        print(f"\n{Colors.BOLD}Enter target website URL:{Colors.ENDC}")
        target_url = input(f"{Colors.OKGREEN}>>> {Colors.ENDC}").strip()
        
        # Validate URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        
        # Validate URL format
        try:
            parsed = urlparse(target_url)
            if not parsed.netloc:
                raise ValueError("Invalid URL")
        except:
            print(f"{Colors.FAIL}[!] Invalid URL format{Colors.ENDC}")
            sys.exit(1)
        
        # Create scanner instance and run
        scanner = WebSpec(target_url)
        scanner.run_scan()
        
    except KeyboardInterrupt:
        print(f"\n\n{Colors.WARNING}[!] Scan interrupted by user{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.FAIL}[!] Fatal error: {str(e)}{Colors.ENDC}")
        sys.exit(1)

if __name__ == "__main__":
    main()
