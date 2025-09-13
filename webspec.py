#!/usr/bin/env python3
"""
Web Spec
Author: TENETx0
GitHub: https://github.com/TENETx0/web-Specter
Version: 1.0
"""

import os
import re
import sys
import ssl
import json
import time
import socket
import hashlib
import requests
import threading
import concurrent.futures
from datetime import datetime
from urllib.parse import urlparse, urljoin
from collections import defaultdict

# Optional imports with fallback
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("[!] python-whois not installed. WHOIS functionality disabled.")

try:
    import dns.resolver
    import dns.query
    import dns.zone
    import dns.message
    import dns.flags
    import dns.dnssec
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print("[!] dnspython not installed. Advanced DNS functionality disabled.")

try:
    import builtwith
    BUILTWITH_AVAILABLE = True
except ImportError:
    BUILTWITH_AVAILABLE = False

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class AdvancedWebEnumerator:
    def __init__(self, target_url):
        self.target_url = self._normalize_url(target_url)
        self.base_domain = urlparse(self.target_url).netloc
        self.domain = self.base_domain.replace('www.', '')
        
        # Session configuration
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 15
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        self.results = {}
        self.loading_done = False
        self.print_lock = threading.Lock()

    def _normalize_url(self, url):
        """Normalize URL format"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')

    def show_loading(self, message):
        """Display loading animation"""
        animation = ['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷']
        idx = 0
        while not self.loading_done:
            with self.print_lock:
                print(f'\r{animation[idx % len(animation)]} {message}...', end='', flush=True)
            idx += 1
            time.sleep(0.1)
        with self.print_lock:
            print(f'\r✓ {message} completed!', end='', flush=True)
            print()

    def get_basic_info(self):
        """Gather basic information about the target"""
        try:
            start_time = time.time()
            response = self.session.get(self.target_url, allow_redirects=True, timeout=15)
            response_time = time.time() - start_time
            
            self.results['status_code'] = response.status_code
            self.results['response_time'] = round(response_time, 2)
            self.results['headers'] = dict(response.headers)
            self.results['final_url'] = response.url
            self.results['content_length'] = len(response.content)
            self.results['response'] = response
            
            return response
        except Exception as e:
            self.results['error'] = str(e)
            return None

    def detect_waf(self, response):
        """Enhanced WAF detection with confidence scoring"""
        waf_signatures = {
            'Cloudflare': {
                'headers': ['cf-ray', 'cf-cache-status', '__cfduid'],
                'cookies': ['__cfduid', 'cf_clearance'],
                'server': ['cloudflare'],
                'content': ['Attention Required! | Cloudflare', 'cf-browser-verification']
            },
            'AWS CloudFront': {
                'headers': ['x-amz-cf-id', 'x-amz-cf-pop'],
                'server': ['CloudFront'],
                'content': []
            },
            'Akamai': {
                'headers': ['akamai-origin-hop', 'akamai-cache-status'],
                'server': ['AkamaiGHost'],
                'content': []
            },
            'Incapsula': {
                'headers': ['x-iinfo', 'x-cdn'],
                'cookies': ['incap_ses', 'visid_incap'],
                'content': ['Incapsula incident']
            },
            'Sucuri': {
                'headers': ['x-sucuri-id', 'x-sucuri-cache'],
                'server': ['Sucuri/Cloudproxy'],
                'content': ['Access Denied - Sucuri Website Firewall']
            },
            'ModSecurity': {
                'headers': [],
                'server': ['mod_security', 'Mod_Security'],
                'content': ['This error was generated by Mod_Security']
            },
            'Barracuda': {
                'headers': [],
                'cookies': ['barra'],
                'content': []
            },
            'F5 BIG-IP': {
                'headers': ['x-wa-info'],
                'cookies': ['BIGipServer'],
                'server': ['BigIP', 'F5'],
                'content': []
            },
            'FortiWeb': {
                'headers': [],
                'cookies': ['FORTIWAFSID'],
                'server': [],
                'content': []
            }
        }
        
        detected_wafs = []
        
        if response:
            headers = {k.lower(): v for k, v in response.headers.items()}
            cookies = {c.name.lower(): c.value for c in response.cookies}
            server = headers.get('server', '').lower()
            content = response.text.lower()
            
            for waf_name, signatures in waf_signatures.items():
                confidence = 0
                matches = []
                
                # Check headers
                for sig in signatures.get('headers', []):
                    if sig.lower() in headers:
                        confidence += 30
                        matches.append(f"Header: {sig}")
                
                # Check cookies
                for sig in signatures.get('cookies', []):
                    if sig.lower() in cookies:
                        confidence += 25
                        matches.append(f"Cookie: {sig}")
                
                # Check server header
                for sig in signatures.get('server', []):
                    if sig.lower() in server:
                        confidence += 35
                        matches.append(f"Server: {sig}")
                
                # Check content
                for sig in signatures.get('content', []):
                    if sig.lower() in content:
                        confidence += 20
                        matches.append(f"Content: {sig[:30]}...")
                
                if confidence > 0:
                    detected_wafs.append({
                        'name': waf_name,
                        'confidence': min(confidence, 100),
                        'matches': matches
                    })
        
        self.results['waf_detection'] = sorted(detected_wafs, key=lambda x: x['confidence'], reverse=True)

    def scan_js_api_keys(self, response):
        """Scan JavaScript files for exposed API keys and secrets"""
        api_key_patterns = {
            'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
            'Firebase API Key': r'AIza[0-9A-Za-z\-_]{35}',
            'Google Cloud Platform API Key': r'AIza[0-9A-Za-z\-_]{35}',
            'Google Maps API Key': r'AIza[0-9A-Za-z\-_]{35}',
            'AWS Access Key ID': r'AKIA[0-9A-Z]{16}',
            'AWS Secret Access Key': r'[0-9a-zA-Z/+=]{40}',
            'Facebook Access Token': r'EAACEdEose0cBA[0-9A-Za-z]+',
            'Twitter Access Token': r'[0-9]{15,25}-[0-9a-zA-Z]{40}',
            'Twitter Bearer Token': r'AA{2}[0-9A-Za-z\-_]{150,}',
            'GitHub Personal Access Token': r'ghp_[0-9A-Za-z]{36}',
            'GitHub OAuth Access Token': r'gho_[0-9A-Za-z]{36}',
            'Stripe API Key': r'sk_live_[0-9a-zA-Z]{24}',
            'Stripe Restricted API Key': r'rk_live_[0-9a-zA-Z]{24}',
            'Square Access Token': r'sq0atp-[0-9A-Za-z\-_]{22}',
            'Square OAuth Secret': r'sq0csp-[0-9A-Za-z\-_]{43}',
            'PayPal Braintree Access Token': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
            'Twilio API Key': r'SK[0-9a-fA-F]{32}',
            'MailGun API Key': r'key-[0-9a-zA-Z]{32}',
            'MailChimp API Key': r'[0-9a-f]{32}-us[0-9]{1,2}',
            'Slack Token': r'xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}',
            'Slack Webhook': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
            'Private Key': r'-----BEGIN (RSA|DSA|EC|PGP) PRIVATE KEY-----',
            'Generic API Key': r'[aA][pP][iI]_?[kK][eE][yY].*[\'\"]\s*[:=]\s*[\'\"]\w{32,}[\'"]',
            'Generic Secret': r'[sS][eE][cC][rR][eE][tT].*[\'\"]\s*[:=]\s*[\'\"]\w{32,}[\'"]',
            'JWT Token': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'
        }
        
        found_keys = []
        
        if response:
            # Scan main HTML
            for key_type, pattern in api_key_patterns.items():
                matches = re.findall(pattern, response.text)
                for match in matches:
                    if len(match) > 10:  # Filter out false positives
                        found_keys.append({
                            'type': key_type,
                            'value': match[:100] + '...' if len(match) > 100 else match,
                            'location': 'Main HTML'
                        })
            
            # Find and scan JavaScript files
            js_files = re.findall(r'<script[^>]*src=["\']([^"\']+\.js[^"\']*)["\']', response.text)
            
            for js_file in js_files[:20]:  # Limit to 20 JS files
                try:
                    js_url = urljoin(self.target_url, js_file)
                    js_response = self.session.get(js_url, timeout=10)
                    
                    for key_type, pattern in api_key_patterns.items():
                        matches = re.findall(pattern, js_response.text)
                        for match in matches:
                            if len(match) > 10:
                                found_keys.append({
                                    'type': key_type,
                                    'value': match[:100] + '...' if len(match) > 100 else match,
                                    'location': js_file
                                })
                except:
                    continue
        
        # Remove duplicates
        unique_keys = []
        seen = set()
        for key in found_keys:
            key_tuple = (key['type'], key['value'][:20])
            if key_tuple not in seen:
                seen.add(key_tuple)
                unique_keys.append(key)
        
        self.results['api_keys_leaked'] = unique_keys

    def enumerate_subdomains(self):
        """Enhanced subdomain enumeration"""
        subdomains_found = []
        
        # Common subdomain wordlist
        wordlist = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2', 
            'cpanel', 'whm', 'autodiscover', 'autoconfig', 'api', 'blog', 'dev', 'staging', 
            'test', 'demo', 'admin', 'portal', 'secure', 'vpn', 'remote', 'cloud', 'storage',
            'backup', 'mx', 'email', 'support', 'help', 'wiki', 'forum', 'shop', 'store',
            'mobile', 'app', 'beta', 'alpha', 'gateway', 'proxy', 'cdn', 'media', 'images',
            'static', 'assets', 'files', 'download', 'upload', 'db', 'database', 'mysql',
            'postgres', 'redis', 'mongodb', 'elastic', 'search', 'api-v1', 'api-v2', 'v1', 'v2',
            'dashboard', 'panel', 'backend', 'frontend', 'web', 'service', 'services', 'rest',
            'graphql', 'grpc', 'websocket', 'ws', 'wss', 'ssh', 'sftp', 'ldap', 'ad',
            'jenkins', 'gitlab', 'github', 'bitbucket', 'jira', 'confluence', 'slack',
            'teams', 'office', 'exchange', 'owa', 'outlook', 'zimbra', 'roundcube',
            'squirrelmail', 'postfix', 'dovecot', 'exim', 'sendmail', 'relay', 'mx1', 'mx2',
            'mx3', 'ns', 'ns3', 'ns4', 'dns', 'dns1', 'dns2', 'resolver', 'ntp', 'time',
            'monitor', 'monitoring', 'nagios', 'zabbix', 'prometheus', 'grafana', 'kibana',
            'logstash', 'elk', 'syslog', 'log', 'logs', 'metrics', 'stats', 'analytics',
            'tracking', 'cdn1', 'cdn2', 'edge', 'origin', 'gateway1', 'gateway2', 'router',
            'firewall', 'waf', 'ids', 'ips', 'siem', 'soc', 'cert', 'pki', 'ca',
            'auth', 'oauth', 'sso', 'saml', 'identity', 'id', 'accounts', 'users'
        ]
        
        print(f"Starting subdomain enumeration for {self.domain}...")
        
        def check_subdomain(subdomain):
            """Check if subdomain exists"""
            full_domain = f"{subdomain}.{self.domain}"
            try:
                # DNS resolution check
                ip_address = socket.gethostbyname(full_domain)
                
                # HTTP/HTTPS connectivity check
                http_status = None
                https_status = None
                technologies = []
                
                try:
                    http_response = self.session.get(f"http://{full_domain}", timeout=5)
                    http_status = http_response.status_code
                    
                    # Basic technology detection
                    if 'apache' in http_response.headers.get('Server', '').lower():
                        technologies.append('Apache')
                    if 'nginx' in http_response.headers.get('Server', '').lower():
                        technologies.append('Nginx')
                    if 'wordpress' in http_response.text.lower():
                        technologies.append('WordPress')
                except:
                    pass
                
                try:
                    https_response = self.session.get(f"https://{full_domain}", timeout=5)
                    https_status = https_response.status_code
                except:
                    pass
                
                return {
                    'subdomain': full_domain,
                    'ip': ip_address,
                    'http_status': http_status,
                    'https_status': https_status,
                    'technologies': technologies
                }
            except:
                return None
        
        # Multi-threaded subdomain checking
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            future_to_subdomain = {executor.submit(check_subdomain, sub): sub for sub in wordlist}
            
            for future in concurrent.futures.as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    subdomains_found.append(result)
                    print(f"[+] Found: {result['subdomain']} ({result['ip']})")
        
        # Certificate Transparency check
        if DNS_AVAILABLE:
            try:
                print("Checking Certificate Transparency logs...")
                ct_url = f"https://crt.sh/?q=%.{self.domain}&output=json"
                ct_response = self.session.get(ct_url, timeout=10)
                
                if ct_response.status_code == 200:
                    ct_data = ct_response.json()
                    ct_domains = set()
                    
                    for entry in ct_data:
                        name_value = entry.get('name_value', '')
                        domains = name_value.split('\n')
                        for domain in domains:
                            if domain and '*' not in domain and domain.endswith(self.domain):
                                ct_domains.add(domain)
                    
                    for domain in ct_domains:
                        if not any(sub['subdomain'] == domain for sub in subdomains_found):
                            try:
                                ip = socket.gethostbyname(domain)
                                subdomains_found.append({
                                    'subdomain': domain,
                                    'ip': ip,
                                    'source': 'Certificate Transparency'
                                })
                                print(f"[+] CT Found: {domain} ({ip})")
                            except:
                                pass
            except Exception as e:
                print(f"Certificate Transparency check failed: {str(e)}")
        
        self.results['subdomains'] = subdomains_found

    def get_dns_mx_records(self):
        """Comprehensive DNS and MX record analysis"""
        dns_records = {}
        
        if DNS_AVAILABLE:
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 5
                resolver.lifetime = 10
                
                # A Records
                try:
                    a_records = resolver.resolve(self.domain, 'A')
                    dns_records['A'] = []
                    for record in a_records:
                        ip = str(record)
                        dns_records['A'].append({
                            'ip': ip,
                            'asn_info': self._get_asn_info(ip)
                        })
                except:
                    dns_records['A'] = []
                
                # AAAA Records
                try:
                    aaaa_records = resolver.resolve(self.domain, 'AAAA')
                    dns_records['AAAA'] = []
                    for record in aaaa_records:
                        dns_records['AAAA'].append({
                            'ipv6': self._compress_ipv6(str(record))
                        })
                except:
                    dns_records['AAAA'] = []
                
                # MX Records
                try:
                    mx_records = resolver.resolve(self.domain, 'MX')
                    dns_records['MX'] = []
                    for mx in mx_records:
                        mx_host = str(mx.exchange).rstrip('.')
                        mx_ip = self._resolve_ip(mx_host)
                        dns_records['MX'].append({
                            'priority': mx.preference,
                            'exchange': mx_host,
                            'ip': mx_ip,
                            'mx_validation': self._validate_mx_server(mx_host),
                            'security_features': self._check_mx_security(mx_host)
                        })
                    dns_records['MX'] = sorted(dns_records['MX'], key=lambda x: x['priority'])
                except:
                    dns_records['MX'] = []
                
                # NS Records
                try:
                    ns_records = resolver.resolve(self.domain, 'NS')
                    dns_records['NS'] = []
                    for ns in ns_records:
                        ns_host = str(ns).rstrip('.')
                        ns_ip = self._resolve_ip(ns_host)
                        dns_records['NS'].append({
                            'nameserver': ns_host,
                            'ip': ns_ip,
                            'authoritative': self._check_authoritative(ns_ip, self.domain),
                            'response_time': self._check_dns_response_time(ns_ip)
                        })
                except:
                    dns_records['NS'] = []
                
                # TXT Records
                try:
                    txt_records = resolver.resolve(self.domain, 'TXT')
                    dns_records['TXT'] = []
                    for txt in txt_records:
                        txt_value = str(txt).strip('"')
                        dns_records['TXT'].append(txt_value)
                except:
                    dns_records['TXT'] = []
                
                # CNAME Records
                try:
                    cname_records = resolver.resolve(self.domain, 'CNAME')
                    dns_records['CNAME'] = []
                    for cname in cname_records:
                        target = str(cname).rstrip('.')
                        dns_records['CNAME'].append({
                            'target': target,
                            'chain_length': self._get_cname_chain_length(target)
                        })
                except:
                    dns_records['CNAME'] = []
                
                # SOA Records
                try:
                    soa_records = resolver.resolve(self.domain, 'SOA')
                    for soa in soa_records:
                        dns_records['SOA'] = {
                            'mname': str(soa.mname),
                            'rname': str(soa.rname),
                            'serial': soa.serial,
                            'refresh': soa.refresh,
                            'retry': soa.retry,
                            'expire': soa.expire,
                            'minimum': soa.minimum,
                            'health': self._analyze_soa_health(soa)
                        }
                except:
                    dns_records['SOA'] = {}
                
                # Email Security Records
                security_records = {}
                
                # SPF Record
                spf_record = None
                for txt in dns_records.get('TXT', []):
                    if 'v=spf1' in txt:
                        spf_record = txt
                        break
                
                if spf_record:
                    security_records['SPF'] = {
                        'record': spf_record,
                        'analysis': self._analyze_spf_record(spf_record),
                        'strength': self._rate_spf_strength(spf_record)
                    }
                
                # DMARC Record
                try:
                    dmarc_records = resolver.resolve(f'_dmarc.{self.domain}', 'TXT')
                    for record in dmarc_records:
                        dmarc_txt = str(record).strip('"')
                        if 'v=DMARC1' in dmarc_txt:
                            security_records['DMARC'] = {
                                'record': dmarc_txt,
                                'analysis': self._analyze_dmarc_record(dmarc_txt),
                                'policy': self._extract_dmarc_policy(dmarc_txt)
                            }
                            break
                except:
                    pass
                
                # DKIM Records (common selectors)
                dkim_selectors = ['default', 'google', 'k1', 'selector1', 'selector2', 'dkim', 'mail']
                dkim_found = []
                
                for selector in dkim_selectors:
                    try:
                        dkim_records = resolver.resolve(f'{selector}._domainkey.{self.domain}', 'TXT')
                        for record in dkim_records:
                            dkim_txt = str(record).strip('"')
                            if 'v=DKIM1' in dkim_txt or 'p=' in dkim_txt:
                                dkim_found.append({
                                    'selector': selector,
                                    'record': dkim_txt[:100] + '...' if len(dkim_txt) > 100 else dkim_txt,
                                    'key_type': self._extract_dkim_key_type(dkim_txt)
                                })
                                break
                    except:
                        pass
                
                if dkim_found:
                    security_records['DKIM'] = dkim_found
                
                dns_records['email_security'] = security_records
                dns_records['email_security_score'] = self._calculate_email_security_score(security_records)
                
                # Additional DNS Security
                dns_records['dnssec'] = self._check_dnssec(self.domain)
                dns_records['dns_over_https'] = self._check_doh_support()
                dns_records['dns_over_tls'] = self._check_dot_support()
                dns_records['vulnerabilities'] = self._check_dns_vulnerabilities()
                
            except Exception as e:
                dns_records['error'] = str(e)
        else:
            # Basic DNS lookup without dnspython
            try:
                ip = socket.gethostbyname(self.domain)
                dns_records['A'] = [{'ip': ip, 'asn_info': 'DNS module not available'}]
            except:
                dns_records['error'] = 'DNS resolution failed'
        
        self.results['dns_records'] = dns_records

    def _get_asn_info(self, ip):
        """Get ASN information for IP (simplified)"""
        try:
            # This would typically use an ASN lookup service
            # For now, return a placeholder
            return "ASN lookup not available"
        except:
            return None

    def _compress_ipv6(self, ipv6):
        """Compress IPv6 address"""
        try:
            import ipaddress
            return str(ipaddress.IPv6Address(ipv6).compressed)
        except:
            return ipv6

    def _resolve_ipv6(self, hostname):
        """Resolve IPv6 address"""
        try:
            if DNS_AVAILABLE:
                import dns.resolver
                resolver = dns.resolver.Resolver()
                answers = resolver.resolve(hostname, 'AAAA')
                return [str(answer) for answer in answers]
        except:
            pass
        return None

    def _validate_mx_server(self, mx_host):
        """Validate MX server connectivity"""
        try:
            import smtplib
            server = smtplib.SMTP(mx_host, 25, timeout=10)
            server.quit()
            return "Reachable"
        except:
            return "Unreachable"

    def _check_mx_security(self, mx_host):
        """Check MX server security features"""
        security_features = []
        try:
            import smtplib
            server = smtplib.SMTP(mx_host, 25, timeout=10)
            
            # Check STARTTLS support
            if server.has_extn('STARTTLS'):
                security_features.append('STARTTLS')
            
            # Check AUTH support
            if server.has_extn('AUTH'):
                security_features.append('AUTH')
                
            server.quit()
        except:
            pass
        
        return security_features

    def _check_authoritative(self, ns, domain):
        """Check if nameserver is authoritative"""
        try:
            if DNS_AVAILABLE:
                import dns.query
                import dns.message
                
                query = dns.message.make_query(domain, 'SOA')
                response = dns.query.udp(query, ns, timeout=5)
                return response.flags & dns.flags.AA != 0
        except:
            pass
        return False

    def _check_dns_response_time(self, ns):
        """Check DNS response time"""
        try:
            if DNS_AVAILABLE:
                import dns.query
                import dns.message
                
                start_time = time.time()
                query = dns.message.make_query(self.domain, 'A')
                dns.query.udp(query, ns, timeout=5)
                return round((time.time() - start_time) * 1000, 2)
        except:
            pass
        return None

    def _analyze_spf_record(self, spf_record):
        """Analyze SPF record for common issues"""
        analysis = []
        
        if '~all' in spf_record:
            analysis.append('Soft fail policy (~all) - less secure')
        elif '-all' in spf_record:
            analysis.append('Hard fail policy (-all) - recommended')
        elif '+all' in spf_record:
            analysis.append('Pass all policy (+all) - not recommended')
        
        if spf_record.count('include:') > 10:
            analysis.append('Too many includes - may cause DNS lookup limit')
            
        if 'redirect=' in spf_record:
            analysis.append('Uses redirect mechanism')
            
        return analysis

    def _rate_spf_strength(self, spf_record):
        """Rate SPF record strength"""
        if '-all' in spf_record:
            return 'Strong'
        elif '~all' in spf_record:
            return 'Moderate'
        elif '?all' in spf_record or '+all' in spf_record:
            return 'Weak'
        else:
            return 'Unknown'

    def _analyze_dmarc_record(self, dmarc_record):
        """Analyze DMARC record"""
        analysis = []
        
        if 'p=none' in dmarc_record:
            analysis.append('Policy: None - monitoring only')
        elif 'p=quarantine' in dmarc_record:
            analysis.append('Policy: Quarantine - suspicious emails quarantined')
        elif 'p=reject' in dmarc_record:
            analysis.append('Policy: Reject - failed emails rejected')
            
        if 'rua=' in dmarc_record:
            analysis.append('Aggregate reports configured')
        if 'ruf=' in dmarc_record:
            analysis.append('Forensic reports configured')
            
        return analysis

    def _extract_dmarc_policy(self, dmarc_record):
        """Extract DMARC policy"""
        if 'p=reject' in dmarc_record:
            return 'reject'
        elif 'p=quarantine' in dmarc_record:
            return 'quarantine'
        elif 'p=none' in dmarc_record:
            return 'none'
        return 'unknown'

    def _extract_dkim_key_type(self, dkim_record):
        """Extract DKIM key type"""
        if 'k=rsa' in dkim_record:
            return 'RSA'
        elif 'k=ed25519' in dkim_record:
            return 'Ed25519'
        return 'Unknown'

    def _calculate_email_security_score(self, security_records):
        """Calculate email security score out of 100"""
        score = 0
        
        # SPF check (25 points)
        if 'SPF' in security_records:
            spf_strength = security_records['SPF'].get('strength', 'Unknown')
            if spf_strength == 'Strong':
                score += 25
            elif spf_strength == 'Moderate':
                score += 15
            elif spf_strength == 'Weak':
                score += 5
        
        # DMARC check (35 points)
        if 'DMARC' in security_records:
            dmarc_policy = security_records['DMARC'].get('policy', 'none')
            if dmarc_policy == 'reject':
                score += 35
            elif dmarc_policy == 'quarantine':
                score += 25
            elif dmarc_policy == 'none':
                score += 10
        
        # DKIM check (25 points)
        if 'DKIM' in security_records and security_records['DKIM']:
            score += 25
        
        # MX security features (15 points)
        mx_records = self.results.get('dns_records', {}).get('MX', [])
        if mx_records:
            for mx in mx_records:
                if 'STARTTLS' in mx.get('security_features', []):
                    score += 15
                    break
        
        return min(score, 100)

    def _get_cname_chain_length(self, target):
        """Get CNAME chain length"""
        try:
            if DNS_AVAILABLE:
                import dns.resolver
                resolver = dns.resolver.Resolver()
                
                chain_length = 0
                current = target
                visited = set()
                
                while current not in visited and chain_length < 10:
                    visited.add(current)
                    try:
                        cname_records = resolver.resolve(current, 'CNAME')
                        current = str(list(cname_records)[0]).rstrip('.')
                        chain_length += 1
                    except:
                        break
                        
                return chain_length
        except:
            pass
        return 0

    def _analyze_soa_health(self, soa):
        """Analyze SOA record health"""
        health_issues = []
        
        if soa.refresh > 86400:  # More than 24 hours
            health_issues.append('Refresh interval too long')
        if soa.retry > 3600:  # More than 1 hour
            health_issues.append('Retry interval too long')
        if soa.expire < 604800:  # Less than 7 days
            health_issues.append('Expire time too short')
        if soa.minimum > 86400:  # More than 24 hours
            health_issues.append('Minimum TTL too long')
            
        return health_issues if health_issues else ['Healthy']

    def _check_dnssec(self, domain):
        """Check DNSSEC support"""
        try:
            if DNS_AVAILABLE:
                import dns.resolver
                
                resolver = dns.resolver.Resolver()
                try:
                    # Try to resolve DS record
                    ds_records = resolver.resolve(domain, 'DS')
                    return True if ds_records else False
                except:
                    return False
        except:
            pass
        return False

    def _check_doh_support(self):
        """Check DNS over HTTPS support"""
        try:
            # Check common DoH endpoints
            doh_endpoints = [
                'https://cloudflare-dns.com/dns-query',
                'https://dns.google/dns-query',
                'https://dns.quad9.net/dns-query'
            ]
            
            for endpoint in doh_endpoints:
                try:
                    response = self.session.get(
                        endpoint,
                        params={'name': self.domain, 'type': 'A'},
                        headers={'Accept': 'application/dns-json'},
                        timeout=5
                    )
                    if response.status_code == 200:
                        return True
                except:
                    continue
            return False
        except:
            return False

    def _check_dot_support(self):
        """Check DNS over TLS support"""
        # This would require specialized DNS over TLS libraries
        # Simplified check for now
        return "Not implemented"

    def _check_dns_vulnerabilities(self):
        """Check for common DNS vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Check for DNS cache poisoning vulnerability (simplified)
            import random
            random_subdomain = f"test-{random.randint(1000, 9999)}.{self.domain}"
            try:
                socket.gethostbyname(random_subdomain)
                vulnerabilities.append("Possible DNS wildcard misconfiguration")
            except:
                pass
                
            # Check for DNS amplification potential
            if DNS_AVAILABLE:
                import dns.resolver
                resolver = dns.resolver.Resolver()
                try:
                    txt_records = resolver.resolve(self.domain, 'TXT')
                    total_size = sum(len(str(record)) for record in txt_records)
                    if total_size > 1000:
                        vulnerabilities.append("Large TXT records - potential amplification vector")
                except:
                    pass
                    
        except:
            pass
            
        return vulnerabilities if vulnerabilities else ["No obvious vulnerabilities detected"]

    def test_cors_security(self):
        """Advanced CORS and cookie security testing with comprehensive analysis"""
        cors_results = {}
        
        print("Testing CORS and cookie security...")
        
        # Enhanced CORS testing with multiple attack vectors
        try:
            # Extended list of test origins for thorough CORS testing
            test_origins = [
                'https://evil.com',
                'https://attacker.com',
                'http://malicious-site.com',
                'null',
                '*',
                self.target_url,
                'https://subdomain.' + self.base_domain,
                'https://' + self.base_domain + '.evil.com',
                'https://evil.com.' + self.base_domain,
                'file://',
                'chrome-extension://fake-extension',
                'moz-extension://fake-extension'
            ]
            
            cors_tests = []
            for origin in test_origins:
                try:
                    headers = {
                        'Origin': origin,
                        'Access-Control-Request-Method': 'POST',
                        'Access-Control-Request-Headers': 'Content-Type, Authorization'
                    }
                    
                    # Preflight request
                    preflight_response = self.session.options(self.target_url, headers=headers, timeout=10)
                    
                    # Actual request
                    actual_response = self.session.get(self.target_url, headers={'Origin': origin}, timeout=10)
                    
                    cors_headers = {
                        'Access-Control-Allow-Origin': actual_response.headers.get('Access-Control-Allow-Origin'),
                        'Access-Control-Allow-Credentials': actual_response.headers.get('Access-Control-Allow-Credentials'),
                        'Access-Control-Allow-Methods': actual_response.headers.get('Access-Control-Allow-Methods'),
                        'Access-Control-Allow-Headers': actual_response.headers.get('Access-Control-Allow-Headers'),
                        'Access-Control-Max-Age': actual_response.headers.get('Access-Control-Max-Age'),
                        'Access-Control-Expose-Headers': actual_response.headers.get('Access-Control-Expose-Headers')
                    }
                    
                    # Filter out None values
                    cors_headers = {k: v for k, v in cors_headers.items() if v is not None}
                    
                    # Vulnerability assessment
                    vulnerabilities = []
                    risk_level = "Low"
                    
                    if cors_headers.get('Access-Control-Allow-Origin') == '*':
                        if cors_headers.get('Access-Control-Allow-Credentials') == 'true':
                            vulnerabilities.append("CRITICAL: Wildcard origin with credentials allowed")
                            risk_level = "Critical"
                        else:
                            vulnerabilities.append("Wildcard origin without credentials")
                            risk_level = "Medium"
                    
                    if cors_headers.get('Access-Control-Allow-Origin') == 'null':
                        vulnerabilities.append("Null origin allowed - potential attack vector")
                        risk_level = "High"
                    
                    if origin in ['https://evil.com', 'https://attacker.com'] and cors_headers.get('Access-Control-Allow-Origin') == origin:
                        vulnerabilities.append(f"Malicious origin {origin} explicitly allowed")
                        risk_level = "High"
                    
                    if cors_headers.get('Access-Control-Allow-Methods') and 'DELETE' in cors_headers.get('Access-Control-Allow-Methods', ''):
                        vulnerabilities.append("Dangerous HTTP methods allowed")
                        if risk_level == "Low":
                            risk_level = "Medium"
                    
                    if cors_headers:
                        cors_tests.append({
                            'test_origin': origin,
                            'cors_headers': cors_headers,
                            'vulnerabilities': vulnerabilities,
                            'risk_level': risk_level,
                            'preflight_status': preflight_response.status_code,
                            'actual_status': actual_response.status_code
                        })
                        
                except Exception as e:
                    cors_tests.append({
                        'test_origin': origin,
                        'error': str(e),
                        'cors_headers': {},
                        'vulnerabilities': [],
                        'risk_level': "Unknown"
                    })
            
            cors_results['cors_tests'] = cors_tests
            
            # CORS security score calculation
            high_risk_count = sum(1 for test in cors_tests if test.get('risk_level') == 'High')
            critical_risk_count = sum(1 for test in cors_tests if test.get('risk_level') == 'Critical')
            
            if critical_risk_count > 0:
                cors_results['cors_security_score'] = 0
            elif high_risk_count > 2:
                cors_results['cors_security_score'] = 25
            elif high_risk_count > 0:
                cors_results['cors_security_score'] = 50
            else:
                cors_results['cors_security_score'] = 100
            
        except Exception as e:
            cors_results['cors_error'] = str(e)
        
        # Enhanced cookie security analysis
        try:
            response = self.session.get(self.target_url, timeout=10)
            cookies_analysis = []
            cookie_security_score = 100
            
            for cookie in response.cookies:
                cookie_info = {
                    'name': cookie.name,
                    'value': cookie.value[:50] + '...' if len(cookie.value) > 50 else cookie.value,
                    'domain': cookie.domain or 'Not set',
                    'path': cookie.path or '/',
                    'secure': cookie.secure,
                    'httponly': self._check_httponly(cookie),
                    'samesite': self._extract_samesite(cookie),
                    'expires': self._format_cookie_expires(cookie.expires),
                    'max_age': getattr(cookie, 'max_age', None)
                }
                
                # Enhanced security assessment
                security_issues = []
                risk_score = 0
                
                # Secure flag check
                if not cookie_info['secure'] and self.target_url.startswith('https'):
                    security_issues.append('Missing Secure flag on HTTPS site')
                    risk_score += 20
                
                # HttpOnly flag check
                if not cookie_info['httponly']:
                    security_issues.append('Missing HttpOnly flag - XSS vulnerability')
                    risk_score += 25
                
                # SameSite attribute check
                if not cookie_info['samesite']:
                    security_issues.append('Missing SameSite attribute - CSRF vulnerability')
                    risk_score += 15
                elif cookie_info['samesite'].lower() == 'none' and not cookie_info['secure']:
                    security_issues.append('SameSite=None without Secure flag')
                    risk_score += 30
                
                # Domain scope check
                if cookie_info['domain'] and cookie_info['domain'].startswith('.'):
                    if cookie_info['domain'].count('.') < 2:
                        security_issues.append('Overly broad domain scope')
                        risk_score += 10
                
                # Path scope check
                if cookie_info['path'] == '/':
                    security_issues.append('Broad path scope - consider restricting')
                    risk_score += 5
                
                # Cookie value analysis
                if self._is_sensitive_cookie(cookie.name, cookie.value):
                    security_issues.append('Potentially sensitive data in cookie')
                    risk_score += 15
                
                # Expiration analysis
                if not cookie_info['expires'] and not cookie_info['max_age']:
                    security_issues.append('Session cookie - good for security')
                elif self._is_long_lived_cookie(cookie.expires):
                    security_issues.append('Long-lived cookie - potential security risk')
                    risk_score += 10
                
                cookie_info['security_issues'] = security_issues
                cookie_info['risk_score'] = min(risk_score, 100)
                cookies_analysis.append(cookie_info)
                
                # Adjust overall cookie security score
                cookie_security_score -= min(risk_score / len(response.cookies) if response.cookies else 1, 20)
            
            cors_results['cookies'] = cookies_analysis
            cors_results['cookie_security_score'] = max(int(cookie_security_score), 0)
            
            # Additional cookie security checks
            cors_results['cookie_analysis'] = {
                'total_cookies': len(response.cookies),
                'secure_cookies': sum(1 for c in cookies_analysis if c['secure']),
                'httponly_cookies': sum(1 for c in cookies_analysis if c['httponly']),
                'samesite_cookies': sum(1 for c in cookies_analysis if c['samesite']),
                'session_cookies': sum(1 for c in cookies_analysis if not c['expires'] and not c['max_age'])
            }
            
        except Exception as e:
            cors_results['cookies_error'] = str(e)
        
        print("CORS and cookie security analysis completed.")
        self.results['cors_cookies'] = cors_results

    def _check_httponly(self, cookie):
        """Check if cookie has HttpOnly flag"""
        return hasattr(cookie, '_rest') and cookie._rest and any('httponly' in str(item).lower() for item in cookie._rest.keys())

    def _extract_samesite(self, cookie):
        """Extract SameSite attribute from cookie"""
        if hasattr(cookie, '_rest') and cookie._rest:
            for key, value in cookie._rest.items():
                if key and str(key).lower() == 'samesite':
                    return value
        return None

    def _format_cookie_expires(self, expires):
        """Format cookie expiration time"""
        if expires:
            try:
                return datetime.fromtimestamp(expires).strftime('%Y-%m-%d %H:%M:%S')
            except:
                return str(expires)
        return None

    def _is_sensitive_cookie(self, name, value):
        """Check if cookie contains sensitive information"""
        sensitive_names = ['session', 'token', 'auth', 'login', 'user', 'admin', 'password', 'key']
        sensitive_patterns = [r'[a-f0-9]{32,}', r'[A-Za-z0-9+/]{20,}={0,2}', r'ey[A-Za-z0-9-_]']
        
        # Check cookie name
        if any(sensitive in name.lower() for sensitive in sensitive_names):
            return True
        
        # Check cookie value patterns
        for pattern in sensitive_patterns:
            if re.search(pattern, value):
                return True
        
        return False

    def _is_long_lived_cookie(self, expires):
        """Check if cookie is long-lived (more than 30 days)"""
        if expires:
            try:
                expiry_time = datetime.fromtimestamp(expires)
                days_until_expiry = (expiry_time - datetime.now()).days
                return days_until_expiry > 30
            except:
                return False
        return False

    def _resolve_ip(self, hostname):
        """Helper function to resolve IP address"""
        try:
            return socket.gethostbyname(hostname.rstrip('.'))
        except:
            return 'Unknown'

    def discover_sensitive_files(self):
        """Advanced sensitive file discovery with intelligent detection"""
        # Comprehensive sensitive file patterns
        sensitive_paths = [
            # Git repositories and version control
            '.git/', '.git/config', '.git/HEAD', '.git/logs/HEAD', '.git/index',
            '.git/refs/heads/master', '.git/refs/heads/main', '.git/objects/',
            '.git/packed-refs', '.git/description', '.git/hooks/', '.git/info/',
            '.gitignore', '.gitattributes', '.gitmodules', '.git/COMMIT_EDITMSG',
            '.svn/', '.svn/entries', '.svn/wc.db', '.hg/', '.hg/hgrc', '.bzr/',
            
            # Environment and configuration files
            '.env', '.env.local', '.env.production', '.env.development', '.env.staging',
            '.env.backup', '.env.example', '.env.sample', '.environment', 'env.js',
            'env.json', '.envrc', 'environment.yml', 'environment.json',
            
            # Application configuration files
            'config.php', 'configuration.php', 'config.json', 'config.xml', 'config.yml',
            'config.yaml', 'config.ini', 'config.properties', 'settings.php',
            'settings.json', 'settings.xml', 'settings.yml', 'app.config',
            'web.config', 'application.yml', 'application.properties', 'database.yml',
            'database.json', 'database.xml', 'wp-config.php', 'wp-config.php.bak',
            'configuration.php-dist', 'config.php.bak', 'config.inc.php',
            
            # Backup and archive files
            'backup/', 'backups/', 'backup.sql', 'backup.tar.gz', 'backup.zip',
            'backup.rar', 'backup.7z', 'db_backup.sql', 'database.sql',
            'dump.sql', 'site.sql', 'backup.tar', 'www.zip', 'www.tar.gz',
            'website.zip', 'site_backup.zip', 'backup_' + datetime.now().strftime('%Y'),
            'backup_' + datetime.now().strftime('%m'), 'old_site.zip',
            
            # Server configuration files
            '.htaccess', '.htpasswd', '.htgroup', 'httpd.conf', 'apache.conf',
            'apache2.conf', 'nginx.conf', 'lighttpd.conf', 'server.xml',
            'server.cfg', 'tomcat-users.xml', '.htaccess.bak', '.htpasswd.bak',
            'php.ini', 'php5.ini', 'my.cnf', 'my.ini', 'postgresql.conf',
            
            # Database files and interfaces
            'database.sqlite', 'database.sqlite3', 'db.sqlite3', 'app.db',
            'data.db', 'database.db', 'users.db', 'phpmyadmin/', 'pma/',
            'adminer.php', 'adminer-4.8.1.php', 'mysql/', 
            'mongod.conf', 'redis.conf', 'elasticsearch.yml',
            
            # Log files
            'error.log', 'access.log', 'error_log', 'access_log', 'debug.log',
            'application.log', 'system.log', 'security.log', 'auth.log',
            'mail.log', 'cron.log', 'logs/', 'log/', 'var/log/', 'temp/', 'tmp/',
            
            # Development files
            'package.json', 'package-lock.json', 'composer.json', 'composer.lock',
            'yarn.lock', 'pnpm-lock.yaml', 'Gemfile', 'Gemfile.lock',
            'requirements.txt', 'requirements-dev.txt', 'pip-log.txt',
            'npm-debug.log', 'yarn-error.log', '.babelrc', '.eslintrc',
            'webpack.config.js', 'gulpfile.js', 'Gruntfile.js', 'tsconfig.json',
            
            # Security and verification files
            'security.txt', '.well-known/security.txt', '.well-known/acme-challenge/',
            'humans.txt', 'robots.txt.bak', 'crossdomain.xml', 'clientaccesspolicy.xml',
            'browserconfig.xml', 'manifest.json', 'site.webmanifest',
            
            # API documentation and testing
            'swagger.json', 'swagger.yml', 'swagger-ui.html', 'openapi.json',
            'openapi.yml', 'api-docs.json', 'postman.json', 'insomnia.json',
            'graphql', 'graphiql', 'playground', 'api/', 'api/v1/', 'api/v2/',
            
            # Cloud and deployment
            '.dockerignore', 'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
            'Dockerfile.prod', '.aws/', '.azure/', '.gcloud/', 'serverless.yml',
            'deploy.sh', 'deployment.yml', 'k8s/', 'kubernetes/',
            '.travis.yml', '.gitlab-ci.yml', '.github/workflows/', 'Jenkinsfile',
            
            # SSH and certificates
            '.ssh/', 'id_rsa', 'id_rsa.pub', 'id_dsa', 'id_dsa.pub',
            'authorized_keys', 'known_hosts', 'ssh_config', 'sshd_config',
            'server.key', 'server.crt', 'private.key', 'certificate.crt',
            'ssl/', 'certs/', 'keys/',
            
            # IDE and editor files
            '.vscode/', '.vscode/settings.json', '.idea/', '.idea/workspace.xml',
            '.sublime-project', '.sublime-workspace', '.project', '.settings/',
            'nbproject/', '.vs/',
            
            # Framework and CMS specific
            'symfony/', 'laravel/', 'codeigniter/', 'cake/', 'yii/', 'zend/',
            'fuel/', 'slim/', 'phalcon/', 'application/', 'system/', 'vendor/',
            'wp-admin/', 'wp-includes/', 'wp-content/', 'admin/', 'administrator/',
            'manager/', 'modx/', 'typo3/', 'joomla/', 'drupal/', 'sites/default/',
            
            # Miscellaneous sensitive files
            'readme.txt', 'README.md', 'CHANGELOG.md', 'TODO.txt',
            'info.php', 'phpinfo.php', 'test.php', 'debug.php',
            'install.php', 'setup.php', 'upgrade.php', 'migration.php'
        ]
        
        found_files = {}
        total_files = len(sensitive_paths)
        
        print(f"Starting comprehensive sensitive file discovery ({total_files} paths)...")
        
        def check_file_advanced(path):
            """Advanced file checking with detailed analysis"""
            try:
                url = urljoin(self.target_url, path)
                
                # Use HEAD request first for efficiency
                head_response = self.session.head(url, timeout=8, allow_redirects=True)
                
                if head_response.status_code in [200, 403, 401]:
                    file_info = {
                        'status_code': head_response.status_code,
                        'size': head_response.headers.get('content-length', 'Unknown'),
                        'content_type': head_response.headers.get('content-type', 'Unknown'),
                        'last_modified': head_response.headers.get('last-modified', 'Unknown'),
                        'etag': head_response.headers.get('etag', 'Unknown'),
                        'server': head_response.headers.get('server', 'Unknown'),
                        'url': url,
                        'content_preview': None,
                        'security_risk': self._assess_file_risk(path, head_response),
                        'file_type': self._classify_file_type(path)
                    }
                    
                    # For high-risk files, try to get content preview
                    if (head_response.status_code == 200 and 
                        any(indicator in path.lower() for indicator in ['.env', 'config', '.git', 'backup', '.ssh'])):
                        try:
                            get_response = self.session.get(url, timeout=8)
                            if get_response.status_code == 200:
                                content = get_response.text[:1000]  # Limit content size
                                # Sanitize sensitive content preview
                                file_info['content_preview'] = self._sanitize_content_preview(content, path)
                                file_info['content_analysis'] = self._analyze_file_content(content, path)
                        except:
                            file_info['content_preview'] = 'Content fetch failed'
                    else:
                        file_info['content_preview'] = 'File exists but content not retrieved'
                    
                    return path, file_info
                    
            except Exception as e:
                # Log connection errors for debugging
                if "timeout" in str(e).lower():
                    return path, {'error': 'Timeout', 'status_code': 'TIMEOUT'}
                
            return None
        
        # Multi-threaded file discovery with progress tracking
        with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
            future_to_path = {executor.submit(check_file_advanced, path): path for path in sensitive_paths}
            completed = 0
            
            for future in concurrent.futures.as_completed(future_to_path):
                completed += 1
                if completed % 15 == 0:
                    progress = (completed / total_files) * 100
                    with self.print_lock:
                        print(f"\rSensitive file scan: {progress:.1f}% ({completed}/{total_files})", end="", flush=True)
                
                result = future.result()
                if result:
                    path, file_info = result
                    if file_info and 'error' not in file_info:
                        found_files[path] = file_info
        
        # Sort found files by risk level and status code
        sorted_files = dict(sorted(
            found_files.items(), 
            key=lambda x: (x[1].get('security_risk', 0), -x[1].get('status_code', 0)),
            reverse=True
        ))
        
        with self.print_lock:
            print(f"\rSensitive file discovery completed. Found {len(sorted_files)} accessible files.")
        
        self.results['sensitive_files'] = sorted_files

    def _assess_file_risk(self, path, response):
        """Assess security risk level of discovered file"""
        high_risk_indicators = [
            '.env', '.git/config', 'wp-config.php', '.htpasswd', 'id_rsa',
            'private.key', 'server.key', 'database.sql', 'backup.sql'
        ]
        
        medium_risk_indicators = [
            'config.php', 'settings.php', '.htaccess', 'phpinfo.php',
            'composer.json', 'package.json', 'web.config'
        ]
        
        if any(indicator in path.lower() for indicator in high_risk_indicators):
            return 100  # High risk
        elif any(indicator in path.lower() for indicator in medium_risk_indicators):
            return 60   # Medium risk
        elif response.status_code == 200:
            return 30   # Low risk
        else:
            return 10   # Info only

    def _classify_file_type(self, path):
        """Classify the type of sensitive file"""
        if any(x in path.lower() for x in ['.env', 'environment']):
            return 'Environment File'
        elif any(x in path.lower() for x in ['config', 'settings']):
            return 'Configuration File'
        elif '.git' in path.lower():
            return 'Version Control'
        elif any(x in path.lower() for x in ['backup', '.sql', 'dump']):
            return 'Backup File'
        elif any(x in path.lower() for x in ['.htaccess', '.htpasswd', 'web.config']):
            return 'Server Configuration'
        elif any(x in path.lower() for x in ['log', 'debug']):
            return 'Log File'
        elif any(x in path.lower() for x in ['key', 'cert', 'pem', '.ssh']):
            return 'Security Credential'
        else:
            return 'Other Sensitive File'

    def _sanitize_content_preview(self, content, path):
        """Sanitize content preview to avoid exposing actual secrets"""
        preview = content[:500]
        
        # Replace potential secrets with placeholders
        # API keys
        preview = re.sub(r'[A-Za-z0-9]{32,}', '[REDACTED_KEY]', preview)
        # Passwords in configs
        preview = re.sub(r'password\s*[=:]\s*[\'"][^\'"\n]+[\'"]', 'password=[REDACTED]', preview, flags=re.IGNORECASE)
        # Database credentials
        preview = re.sub(r'(username|user|login)\s*[=:]\s*[\'"][^\'"\n]+[\'"]', r'\1=[REDACTED]', preview, flags=re.IGNORECASE)
        
        return preview

    def _analyze_file_content(self, content, path):
        """Analyze file content for security implications"""
        analysis = []
        
        # Check for common sensitive patterns
        if re.search(r'password\s*[=:]', content, re.IGNORECASE):
            analysis.append('Contains password fields')
        
        if re.search(r'api[_-]?key', content, re.IGNORECASE):
            analysis.append('Contains API key references')
            
        if re.search(r'secret[_-]?key', content, re.IGNORECASE):
            analysis.append('Contains secret key references')
            
        if re.search(r'database.*connection', content, re.IGNORECASE):
            analysis.append('Contains database connection info')
            
        if '.env' in path.lower():
            env_vars = len(re.findall(r'^\w+\s*=', content, re.MULTILINE))
            analysis.append(f'Environment file with {env_vars} variables')
        
        return analysis

    def detect_technology_stack(self, response):
        """Enhanced technology stack detection"""
        tech_stack = {
            'frontend': [],
            'backend': [],
            'database': [],
            'server': [],
            'frameworks': [],
            'cms': [],
            'javascript_libraries': [],
            'css_frameworks': []
        }

        if response:
            headers = response.headers
            content = response.text.lower()

            # Enhanced server detection
            server = headers.get('Server', '').lower()
            if server:
                tech_stack['server'].append(headers.get('Server'))
                if 'apache' in server:
                    tech_stack['server'].append('Apache HTTP Server')
                elif 'nginx' in server:
                    tech_stack['server'].append('Nginx')
                elif 'iis' in server:
                    tech_stack['server'].append('Microsoft IIS')
                elif 'cloudflare' in server:
                    tech_stack['server'].append('Cloudflare')

            # Enhanced backend framework detection
            powered_by = headers.get('X-Powered-By', '').lower()
            if powered_by:
                tech_stack['backend'].append(headers.get('X-Powered-By'))

            # Comprehensive framework detection
            frameworks = {
                # JavaScript Frameworks
                'react': ['react', '_react', 'react-dom', 'react-router'],
                'angular': ['angular', 'ng-', 'angular.js', '@angular'],
                'vue': ['vue.js', 'vue-', '__vue__', 'vuejs'],
                'ember': ['ember', 'ember.js', 'emberjs'],
                'backbone': ['backbone', 'backbone.js'],
                'knockout': ['knockout', 'ko.observable'],
                'meteor': ['meteor', 'meteorjs'],
                'svelte': ['svelte', '_svelte'],
                
                # CSS Frameworks
                'bootstrap': ['bootstrap', 'btn-', 'col-', 'container-fluid'],
                'foundation': ['foundation', 'fi-', 'callout'],
                'bulma': ['bulma', 'hero-', 'navbar-'],
                'materialize': ['materialize', 'material-icons'],
                'semantic-ui': ['semantic', 'ui segment'],
                'tailwind': ['tailwind', 'tw-'],
                
                # Backend Frameworks
                'express': ['express', 'expressjs'],
                'django': ['django', 'csrf', 'djangoproject'],
                'flask': ['flask', 'werkzeug'],
                'laravel': ['laravel', 'laravel_session', 'illuminate'],
                'symfony': ['symfony', 'sf-toolbar'],
                'codeigniter': ['codeigniter', 'ci_session'],
                'cakephp': ['cakephp', 'cake_'],
                'zend': ['zend', 'zf2', 'zf3'],
                'rails': ['rails', 'ruby on rails', 'csrf-param'],
                'spring': ['spring', 'springframework'],
                'aspnet': ['asp.net', 'aspnet', '__viewstate'],
                'fastapi': ['fastapi', 'swagger'],
                'nestjs': ['nestjs', '@nestjs'],
                
                # CMS Detection
                'wordpress': ['wp-content', 'wp-includes', 'wordpress', 'wp-json'],
                'drupal': ['drupal', 'sites/all', 'drupal.org'],
                'joomla': ['joomla', '/components/', 'com_content'],
                'magento': ['magento', 'mage/cookies.js'],
                'shopify': ['shopify', 'shop.js', 'shopifycdn'],
                'woocommerce': ['woocommerce', 'wc-'],
                'prestashop': ['prestashop', 'ps_'],
                'opencart': ['opencart', 'catalog/view'],
                'ghost': ['ghost', 'ghost.org'],
                'typo3': ['typo3', 'typo3conf'],
                'concrete5': ['concrete5', 'ccm_'],
                'umbraco': ['umbraco', 'umbraco.aspx'],
                
                # Other Frameworks
                'nextjs': ['next.js', '_next', 'next/'],
                'nuxt': ['nuxt', '_nuxt'],
                'gatsby': ['gatsby', 'gatsby-'],
                'webpack': ['webpack', '__webpack'],
                'parcel': ['parcel', 'parcel-bundler'],
                'rollup': ['rollup', 'rollupjs']
            }

            for framework, indicators in frameworks.items():
                if any(indicator in content for indicator in indicators):
                    if framework in ['react', 'angular', 'vue', 'ember', 'backbone', 'knockout', 'meteor', 'svelte']:
                        tech_stack['javascript_libraries'].append(framework.title())
                    elif framework in ['bootstrap', 'foundation', 'bulma', 'materialize', 'semantic-ui', 'tailwind']:
                        tech_stack['css_frameworks'].append(framework.title())
                    elif framework in ['wordpress', 'drupal', 'joomla', 'magento', 'shopify', 'ghost', 'typo3', 'concrete5', 'umbraco']:
                        tech_stack['cms'].append(framework.title())
                    else:
                        tech_stack['frameworks'].append(framework.title())

            # Enhanced database detection
            db_indicators = {
                'mysql': ['mysql', 'phpmyadmin', 'mysqli'],
                'postgresql': ['postgresql', 'postgres', 'psql'],
                'mongodb': ['mongodb', 'mongo', 'bson'],
                'redis': ['redis', 'redis-server'],
                'sqlite': ['sqlite', 'sqlite3'],
                'oracle': ['oracle', 'oci8'],
                'mssql': ['mssql', 'sqlserver', 'microsoft sql'],
                'cassandra': ['cassandra', 'cql'],
                'elasticsearch': ['elasticsearch', 'elastic'],
                'neo4j': ['neo4j', 'cypher'],
                'couchdb': ['couchdb', 'couch'],
                'firebase': ['firebase', 'firestore'],
                'dynamodb': ['dynamodb', 'aws-sdk'],
                'influxdb': ['influxdb', 'influx'],
                'mariadb': ['mariadb', 'maria']
            }

            for db, indicators in db_indicators.items():
                if any(indicator in content or indicator in str(headers).lower() for indicator in indicators):
                    tech_stack['database'].append(db.upper())

        # Enhanced builtwith detection
        if BUILTWITH_AVAILABLE:
            try:
                builtwith_result = builtwith.parse(self.target_url)
                for category, technologies in builtwith_result.items():
                    if category.lower() in ['web-frameworks', 'javascript-frameworks']:
                        tech_stack['frameworks'].extend(technologies)
                    elif 'server' in category.lower():
                        tech_stack['server'].extend(technologies)
                    elif 'database' in category.lower():
                        tech_stack['database'].extend(technologies)
                    elif 'cms' in category.lower():
                        tech_stack['cms'].extend(technologies)
            except:
                pass

        # Remove duplicates and clean up
        for key in tech_stack:
            tech_stack[key] = list(set(tech_stack[key]))

        # Enhanced stack type determination
        stack_type = "Custom Stack"
        frameworks = [f.lower() for f in tech_stack['frameworks'] + tech_stack['javascript_libraries']]
        cms = [c.lower() for c in tech_stack['cms']]
        databases = [d.lower() for d in tech_stack['database']]
        
        if 'wordpress' in cms:
            stack_type = "WordPress Stack"
        elif 'drupal' in cms:
            stack_type = "Drupal Stack"
        elif 'joomla' in cms:
            stack_type = "Joomla Stack"
        elif any(x in frameworks for x in ['react', 'angular', 'vue']) and any(x in frameworks for x in ['express', 'node']):
            if 'mongodb' in databases:
                stack_type = "MEAN/MERN Stack"
            else:
                stack_type = "Modern JavaScript Stack"
        elif any(x in frameworks for x in ['laravel', 'symfony']) or 'php' in str(tech_stack['server']).lower():
            if 'mysql' in databases:
                stack_type = "LAMP Stack"
            else:
                stack_type = "PHP Stack"
        elif 'django' in frameworks or 'flask' in frameworks:
            stack_type = "Python Stack"
        elif 'rails' in frameworks:
            stack_type = "Ruby on Rails Stack"
        elif 'spring' in frameworks:
            stack_type = "Java Spring Stack"
        elif 'aspnet' in frameworks:
            stack_type = ".NET Stack"

        self.results['technology_stack'] = tech_stack
        self.results['stack_type'] = stack_type

    def get_robots_txt(self):
        """Fetch robots.txt with detailed analysis"""
        try:
            robots_url = urljoin(self.target_url, '/robots.txt')
            response = self.session.get(robots_url, timeout=10)
            if response.status_code == 200:
                robots_content = response.text
                self.results['robots_txt'] = robots_content
                
                # Analyze robots.txt for interesting information
                disallow_patterns = re.findall(r'Disallow:\s*([^\r\n]+)', robots_content, re.IGNORECASE)
                allow_patterns = re.findall(r'Allow:\s*([^\r\n]+)', robots_content, re.IGNORECASE)
                sitemaps = re.findall(r'Sitemap:\s*([^\r\n]+)', robots_content, re.IGNORECASE)
                
                self.results['robots_analysis'] = {
                    'disallowed_paths': disallow_patterns,
                    'allowed_paths': allow_patterns,
                    'sitemaps': sitemaps
                }
            else:
                self.results['robots_txt'] = f"Not found (Status: {response.status_code})"
                self.results['robots_analysis'] = {}
        except Exception as e:
            self.results['robots_txt'] = f"Not accessible: {str(e)}"
            self.results['robots_analysis'] = {}

    def get_comprehensive_security_headers(self):
        """Enhanced security headers analysis"""
        security_headers = {
            # Core Security Headers
            'Content-Security-Policy': 'Content Security Policy - Prevents XSS and data injection',
            'X-Frame-Options': 'Click-jacking protection',
            'X-XSS-Protection': 'Legacy XSS protection (deprecated)',
            'X-Content-Type-Options': 'MIME sniffing protection',
            'Strict-Transport-Security': 'HTTP Strict Transport Security (HSTS)',
            'Referrer-Policy': 'Controls referrer information',
            'Permissions-Policy': 'Feature policy for web APIs',
            'Cross-Origin-Embedder-Policy': 'Cross-origin isolation',
            'Cross-Origin-Opener-Policy': 'Cross-origin window policy',
            'Cross-Origin-Resource-Policy': 'Cross-origin resource sharing policy',
            
            # Additional Security Headers
            'X-Permitted-Cross-Domain-Policies': 'Adobe Flash/PDF cross-domain policy',
            'X-Download-Options': 'IE download behavior',
            'X-DNS-Prefetch-Control': 'DNS prefetching control',
            'Expect-CT': 'Certificate Transparency enforcement',
            'Public-Key-Pins': 'HTTP Public Key Pinning (deprecated)',
            'Public-Key-Pins-Report-Only': 'HPKP reporting mode',
            'Content-Security-Policy-Report-Only': 'CSP reporting mode',
            'Feature-Policy': 'Legacy feature policy (replaced by Permissions-Policy)',
            
            # Cache and Proxy Headers
            'Cache-Control': 'Cache behavior control',
            'Pragma': 'Legacy cache control',
            'Expires': 'Resource expiration time',
            'X-Cache': 'CDN/Proxy cache status',
            'X-Served-By': 'Server identification',
            'X-Cache-Status': 'Cache hit/miss status',
            'Via': 'Proxy chain information',
            
            # Application Security
            'X-Robots-Tag': 'Robot indexing control',
            'X-UA-Compatible': 'IE compatibility mode',
            'X-Request-ID': 'Request tracking',
            'X-Correlation-ID': 'Request correlation',
            'X-Rate-Limit-Limit': 'Rate limiting information',
            'X-Rate-Limit-Remaining': 'Rate limit remaining',
            'X-Rate-Limit-Reset': 'Rate limit reset time'
        }
        
        found_headers = {}
        missing_headers = []
        
        headers = self.results.get('headers', {})
        
        for header, description in security_headers.items():
            header_variations = [header, header.lower(), header.replace('-', '_').lower()]
            found = False
            
            for variation in header_variations:
                if variation in headers or any(variation == h.lower() for h in headers.keys()):
                    # Find the actual header name used
                    actual_header = next((h for h in headers.keys() if h.lower() == variation), header)
                    found_headers[header] = {
                        'value': headers.get(actual_header, ''),
                        'description': description,
                        'header_name': actual_header
                    }
                    found = True
                    break
            
            if not found and header in ['Content-Security-Policy', 'X-Frame-Options', 'Strict-Transport-Security', 'X-Content-Type-Options']:
                missing_headers.append(header)
        
        self.results['security_headers'] = found_headers
        self.results['missing_critical_headers'] = missing_headers

    def get_detailed_ssl_info(self):
        """Comprehensive SSL/TLS certificate analysis"""
        try:
            hostname = urlparse(self.target_url).netloc
            port = 443
            
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cert_der = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    protocol_version = ssock.version()
                    
            # Calculate certificate fingerprints
            sha1_fingerprint = hashlib.sha1(cert_der).hexdigest()
            sha256_fingerprint = hashlib.sha256(cert_der).hexdigest()
            md5_fingerprint = hashlib.md5(cert_der).hexdigest()
            
            # Parse certificate details
            subject = dict(x[0] for x in cert.get('subject', []))
            issuer = dict(x[0] for x in cert.get('issuer', []))
            
            # Get Subject Alternative Names
            san_list = []
            for ext in cert.get('subjectAltName', []):
                if ext[0] == 'DNS':
                    san_list.append(ext[1])
            
            # Certificate validation dates
            not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_until_expiry = (not_after - datetime.now()).days
            
            # Determine certificate authority type
            ca_type = "Unknown CA"
            issuer_org = issuer.get('organizationName', '').lower()
            if 'let\'s encrypt' in issuer_org:
                ca_type = "Let's Encrypt (Free)"
            elif 'cloudflare' in issuer_org:
                ca_type = "Cloudflare"
            elif 'digicert' in issuer_org:
                ca_type = "DigiCert (Commercial)"
            elif 'godaddy' in issuer_org:
                ca_type = "GoDaddy (Commercial)"
            elif 'comodo' in issuer_org or 'sectigo' in issuer_org:
                ca_type = "Sectigo/Comodo (Commercial)"
            elif 'globalsign' in issuer_org:
                ca_type = "GlobalSign (Commercial)"
            
            # SSL/TLS security analysis
            security_issues = []
            if protocol_version in ['TLSv1', 'TLSv1.1']:
                security_issues.append(f"Outdated protocol: {protocol_version}")
            if days_until_expiry < 30:
                security_issues.append(f"Certificate expires soon ({days_until_expiry} days)")
            if days_until_expiry < 0:
                security_issues.append("Certificate has expired!")
                
            self.results['ssl_info'] = {
                'subject': subject,
                'issuer': issuer,
                'version': cert.get('version', 'Unknown'),
                'serial_number': cert.get('serialNumber', 'Unknown'),
                'not_before': cert['notBefore'],
                'not_after': cert['notAfter'],
                'days_until_expiry': days_until_expiry,
                'subject_alt_names': san_list,
                'fingerprints': {
                    'sha1': ':'.join([sha1_fingerprint[i:i+2] for i in range(0, len(sha1_fingerprint), 2)]).upper(),
                    'sha256': ':'.join([sha256_fingerprint[i:i+2] for i in range(0, len(sha256_fingerprint), 2)]).upper(),
                    'md5': ':'.join([md5_fingerprint[i:i+2] for i in range(0, len(md5_fingerprint), 2)]).upper()
                },
                'cipher_suite': cipher[0] if cipher else 'Unknown',
                'cipher_version': cipher[1] if cipher and len(cipher) > 1 else 'Unknown',
                'cipher_bits': cipher[2] if cipher and len(cipher) > 2 else 'Unknown',
                'protocol_version': protocol_version,
                'ca_type': ca_type,
                'security_issues': security_issues,
                'key_size': cert.get('keySize', 'Unknown')
            }
            
        except Exception as e:
            self.results['ssl_info'] = f"SSL information not available: {str(e)}"

    def deep_plugin_detection(self, response):
        """Enhanced plugin and library detection"""
        plugins = {}
        versions = {}
        
        if response:
            content = response.text
            headers = response.headers
            
            # WordPress comprehensive detection
            wp_plugins = re.findall(r'wp-content/plugins/([^/\'"?\s]+)', content, re.IGNORECASE)
            wp_themes = re.findall(r'wp-content/themes/([^/\'"?\s]+)', content, re.IGNORECASE)
            
            if wp_plugins:
                plugins['WordPress Plugins'] = list(set(wp_plugins))
            if wp_themes:
                plugins['WordPress Themes'] = list(set(wp_themes))
            
            # JavaScript libraries with detailed version detection
            js_patterns = {
                'jquery': [r'jquery[.-]?v?(\d+\.\d+\.\d+)', r'jquery[/-](\d+\.\d+\.\d+)'],
                'bootstrap': [r'bootstrap[.-]?v?(\d+\.\d+\.\d+)', r'bootstrap[/-](\d+\.\d+\.\d+)'],
                'angular': [r'angular[.-]?v?(\d+\.\d+\.\d+)', r'@angular/core.*?(\d+\.\d+\.\d+)'],
                'react': [r'react[.-]?v?(\d+\.\d+\.\d+)', r'react@(\d+\.\d+\.\d+)'],
                'vue': [r'vue[.-]?v?(\d+\.\d+\.\d+)', r'vue@(\d+\.\d+\.\d+)'],
                'lodash': [r'lodash[.-]?v?(\d+\.\d+\.\d+)', r'lodash@(\d+\.\d+\.\d+)'],
                'moment': [r'moment[.-]?v?(\d+\.\d+\.\d+)', r'moment@(\d+\.\d+\.\d+)'],
                'chart.js': [r'chart\.js[.-]?v?(\d+\.\d+\.\d+)', r'chartjs@(\d+\.\d+\.\d+)'],
                'd3': [r'd3[.-]?v?(\d+\.\d+\.\d+)', r'd3@(\d+\.\d+\.\d+)'],
                'leaflet': [r'leaflet[.-]?v?(\d+\.\d+\.\d+)', r'leaflet@(\d+\.\d+\.\d+)']
            }
            
            for lib, patterns in js_patterns.items():
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        versions[lib] = list(set(matches))
                        break
            
            # Server software versions from headers
            server_header = headers.get('Server', '')
            server_matches = re.findall(r'([a-zA-Z]+)/([0-9.]+)', server_header)
            if server_matches:
                for software, version in server_matches:
                    versions[f'{software} Server'] = [version]
            
            # PHP version detection
            php_version = headers.get('X-Powered-By', '')
            php_match = re.search(r'PHP/([0-9.]+)', php_version)
            if php_match:
                versions['PHP'] = [php_match.group(1)]
        
        self.results['plugins_detailed'] = plugins
        self.results['versions_detected'] = versions

    def get_comprehensive_whois(self):
        """Detailed WHOIS information gathering"""
        if not WHOIS_AVAILABLE:
            self.results['whois_detailed'] = {
                'error': 'WHOIS module not available - install python-whois',
                'domain_name': self.base_domain
            }
            return
        
        try:
            domain_name = self.base_domain
            
            w = whois.whois(domain_name)
            
            # Extract and format WHOIS data
            whois_data = {
                'domain_name': getattr(w, 'domain_name', 'Unknown'),
                'registrar': getattr(w, 'registrar', 'Unknown'),
                'whois_server': getattr(w, 'whois_server', 'Unknown'),
                'creation_date': self._format_date(getattr(w, 'creation_date', None)),
                'expiration_date': self._format_date(getattr(w, 'expiration_date', None)),
                'updated_date': self._format_date(getattr(w, 'updated_date', None)),
                'status': getattr(w, 'status', []),
                'name_servers': getattr(w, 'name_servers', []),
                'registrant_name': getattr(w, 'registrant_name', 'Unknown'),
                'registrant_organization': getattr(w, 'registrant_organization', 'Unknown'),
                'registrant_country': getattr(w, 'registrant_country', 'Unknown'),
                'admin_email': getattr(w, 'admin_email', 'Unknown'),
                'tech_email': getattr(w, 'tech_email', 'Unknown'),
                'dnssec': getattr(w, 'dnssec', 'Unknown'),
                'org': getattr(w, 'org', 'Unknown'),
                'country': getattr(w, 'country', 'Unknown'),
                'state': getattr(w, 'state', 'Unknown'),
                'city': getattr(w, 'city', 'Unknown'),
                'address': getattr(w, 'address', 'Unknown'),
                'zipcode': getattr(w, 'zipcode', 'Unknown'),
                'phone': getattr(w, 'phone', 'Unknown'),
                'fax': getattr(w, 'fax', 'Unknown'),
                'emails': getattr(w, 'emails', [])
            }
            
            # Calculate domain age
            if whois_data['creation_date'] and whois_data['creation_date'] != 'Unknown':
                try:
                    if isinstance(whois_data['creation_date'], list):
                        creation_date = whois_data['creation_date'][0]
                    else:
                        creation_date = whois_data['creation_date']
                    
                    if isinstance(creation_date, str):
                        creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
                    
                    domain_age = (datetime.now() - creation_date).days
                    whois_data['domain_age_days'] = domain_age
                    whois_data['domain_age_years'] = round(domain_age / 365.25, 2)
                except:
                    whois_data['domain_age_days'] = 'Unknown'
                    whois_data['domain_age_years'] = 'Unknown'
            
            # Clean up lists and convert to strings if needed
            for key, value in whois_data.items():
                if isinstance(value, list):
                    if len(value) == 1:
                        whois_data[key] = value[0] if value[0] else 'Unknown'
                    elif len(value) > 1:
                        whois_data[key] = value
                    else:
                        whois_data[key] = 'Unknown'
                elif value is None or value == '':
                    whois_data[key] = 'Unknown'
            
            self.results['whois_detailed'] = whois_data
            
        except Exception as e:
            self.results['whois_detailed'] = {
                'error': f"WHOIS information not available: {str(e)}",
                'domain_name': self.base_domain
            }

    def _format_date(self, date_value):
        """Format date values from WHOIS data"""
        if not date_value:
            return 'Unknown'
        
        if isinstance(date_value, list):
            date_value = date_value[0] if date_value else None
        
        if isinstance(date_value, datetime):
            return date_value.strftime('%Y-%m-%d')
        elif isinstance(date_value, str):
            return date_value
        else:
            return str(date_value) if date_value else 'Unknown'

    def run_comprehensive_analysis(self):
        """Run complete enhanced analysis with all new features"""
        phases = [
            ("Basic Information", self.get_basic_info),
            ("WAF Detection", lambda r: self.detect_waf(r)),
            ("Technology Stack", lambda r: self.detect_technology_stack(r)),
            ("API Key Scanning", lambda r: self.scan_js_api_keys(r)),
            ("Subdomain Enumeration", lambda: self.enumerate_subdomains()),
            ("DNS/MX Records", lambda: self.get_dns_mx_records()),
            ("CORS/Cookie Security", lambda: self.test_cors_security()),
            ("Security Headers", lambda: self.get_comprehensive_security_headers()),
            ("SSL/TLS Analysis", lambda: self.get_detailed_ssl_info()),
            ("Plugin Detection", lambda r: self.deep_plugin_detection(r)),
            ("WHOIS Information", lambda: self.get_comprehensive_whois()),
            ("Robots.txt Analysis", lambda: self.get_robots_txt()),
            ("Sensitive Files", lambda: self.discover_sensitive_files())
        ]
        
        try:
            # Phase 1: Basic Information
            self.loading_done = False
            loading_thread = threading.Thread(target=self.show_loading, args=("Gathering basic information",))
            loading_thread.daemon = True
            loading_thread.start()
            
            response = self.get_basic_info()
            self.loading_done = True
            loading_thread.join()
            
            if not response:
                print("Failed to connect to target website!")
                return False
            
            print("Basic information gathered successfully.")
            
            # Run all other phases
            for phase_name, phase_func in phases[1:]:
                print(f"Running {phase_name}...")
                try:
                    if phase_name in ["WAF Detection", "Technology Stack", "API Key Scanning", "Plugin Detection"]:
                        phase_func(response)
                    else:
                        phase_func()
                    print(f"{phase_name} completed.")
                except Exception as e:
                    print(f"Error in {phase_name}: {str(e)}")
                    continue
            
            print("\nAnalysis completed successfully!")
            return True
            
        except KeyboardInterrupt:
            print("\n\nAnalysis interrupted by user!")
            return False
        except Exception as e:
            print(f"\nAn error occurred during analysis: {str(e)}")
            return False

    def generate_advanced_html_report(self):
        """Generate comprehensive HTML report with all new features"""
        domain_name = self.domain.replace('.', '_')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{domain_name}_advanced_report_{timestamp}.html"
        
        # Helper function to format lists safely
        def format_list_safe(items, item_type="item"):
            if not items:
                return f"<li>No {item_type}s detected</li>"
            if isinstance(items, dict):
                result = ""
                for key, value in items.items():
                    if isinstance(value, list):
                        value = ", ".join(map(str, value))
                    result += f"<li><strong>{key}:</strong> {value}</li>"
                return result
            if isinstance(items, list):
                return "".join([f"<li>{item}</li>" for item in items])
            return f"<li>{items}</li>"
        
        # Get data with fallbacks
        security_headers = self.results.get("security_headers", {})
        subdomains = self.results.get("subdomains", [])
        api_keys = self.results.get("api_keys_leaked", [])
        sensitive_files = self.results.get("sensitive_files", {})
        waf_detection = self.results.get("waf_detection", [])
        tech_stack = self.results.get("technology_stack", {})

# NEW FIX
        ssl_info = self.results.get("ssl_info") or {}
        if isinstance(ssl_info, str):
         ssl_info = {"Info": ssl_info}

        whois_info = self.results.get("whois_detailed") or {}
        if isinstance(whois_info, str):
         whois_info = {"WHOIS": whois_info}

        dns_records = self.results.get("dns_records") or []

        cors_cookies = self.results.get("cors_cookies") or {}
        if isinstance(cors_cookies, str):
         cors_cookies = {"CORS": cors_cookies}

        plugins = self.results.get("plugins_detailed") or []
        versions = self.results.get("versions_detected") or {}
        if isinstance(versions, list):
         versions = {f"Item {i+1}": v for i,v in enumerate(versions)}
        elif isinstance(versions, str):
         versions = {"Version": versions}

        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Advanced Web Enumeration Report - {self.domain}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1600px;
            margin: 20px auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 25px 50px rgba(0,0,0,0.15);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 50px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }}
        
        .header::before {{
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: repeating-linear-gradient(
                45deg,
                transparent,
                transparent 2px,
                rgba(255,255,255,0.05) 2px,
                rgba(255,255,255,0.05) 4px
            );
            animation: slide 30s linear infinite;
        }}
        
        @keyframes slide {{
            0% {{ transform: translateX(-100px) translateY(-100px); }}
            100% {{ transform: translateX(100px) translateY(100px); }}
        }}
        
        .header h1 {{
            font-size: 3.5em;
            margin-bottom: 15px;
            position: relative;
            z-index: 1;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        
        .header .subtitle {{
            font-size: 1.3em;
            opacity: 0.9;
            position: relative;
            z-index: 1;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 25px;
            padding: 40px;
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
        }}
        
        .stat-card {{
            background: white;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
            text-align: center;
            transition: all 0.3s ease;
            border-top: 4px solid #667eea;
        }}
        
        .stat-card:hover {{
            transform: translateY(-8px);
            box-shadow: 0 15px 35px rgba(0,0,0,0.2);
        }}
        
        .stat-number {{
            font-size: 3em;
            font-weight: bold;
            background: linear-gradient(45deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        
        .stat-label {{
            color: #666;
            font-size: 1em;
            margin-top: 8px;
            font-weight: 500;
        }}
        
        .section {{
            padding: 40px;
            border-bottom: 2px solid #eee;
        }}
        
        .section:last-child {{
            border-bottom: none;
        }}
        
        h2 {{
            color: #2c3e50;
            font-size: 2.2em;
            margin-bottom: 30px;
            border-left: 6px solid #667eea;
            padding-left: 20px;
            background: linear-gradient(90deg, rgba(102,126,234,0.1) 0%, transparent 100%);
            padding-top: 15px;
            padding-bottom: 15px;
        }}
        
        h3 {{
            color: #34495e;
            margin-bottom: 20px;
            font-size: 1.4em;
            border-bottom: 2px solid #ecf0f1;
            padding-bottom: 10px;
        }}
        
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
            margin-bottom: 30px;
        }}
        
        .info-card {{
            background: linear-gradient(145deg, #ffffff, #f8f9fa);
            padding: 25px;
            border-radius: 15px;
            border-left: 5px solid #667eea;
            box-shadow: 0 8px 20px rgba(0,0,0,0.1);
            transition: all 0.3s ease;
        }}
        
        .info-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 12px 30px rgba(0,0,0,0.15);
        }}
        
        .info-card.critical {{
            border-left-color: #e74c3c;
        }}
        
        .info-card.warning {{
            border-left-color: #f39c12;
        }}
        
        .info-card.success {{
            border-left-color: #27ae60;
        }}
        
        .tech-stack {{
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 15px;
        }}
        
        .tech-badge {{
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
            padding: 8px 16px;
            border-radius: 25px;
            font-size: 0.9em;
            font-weight: 500;
            box-shadow: 0 3px 10px rgba(102,126,234,0.3);
            transition: all 0.3s ease;
        }}
        
        .tech-badge:hover {{
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102,126,234,0.5);
        }}
        
        .status-good {{ background: linear-gradient(45deg, #27ae60, #2ecc71); }}
        .status-warning {{ background: linear-gradient(45deg, #f39c12, #e67e22); }}
        .status-danger {{ background: linear-gradient(45deg, #e74c3c, #c0392b); }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 25px 0;
            background: white;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
        }}
        
        th {{
            background: linear-gradient(45deg, #2c3e50, #34495e);
            color: white;
            padding: 18px;
            text-align: left;
            font-weight: 600;
            font-size: 1.1em;
        }}
        
        td {{
            padding: 15px 18px;
            border-bottom: 1px solid #ecf0f1;
        }}
        
        tr:hover {{
            background: linear-gradient(90deg, rgba(102,126,234,0.05) 0%, transparent 100%);
        }}
        
        .code-block {{
            background: #2c3e50;
            color: #ecf0f1;
            padding: 25px;
            border-radius: 12px;
            font-family: 'Courier New', monospace;
            white-space: pre-wrap;
            max-height: 500px;
            overflow-y: auto;
            margin: 20px 0;
            box-shadow: inset 0 4px 15px rgba(0,0,0,0.3);
            border-left: 5px solid #3498db;
        }}
        
        .vulnerability-item {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px;
            margin: 10px 0;
            background: white;
            border-radius: 8px;
            border-left: 4px solid #e74c3c;
            box-shadow: 0 3px 10px rgba(0,0,0,0.1);
        }}
        
        .vulnerability-high {{ border-left-color: #e74c3c; }}
        .vulnerability-medium {{ border-left-color: #f39c12; }}
        .vulnerability-low {{ border-left-color: #f1c40f; }}
        .vulnerability-info {{ border-left-color: #3498db; }}
        
        .footer {{
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        
        .developer-info {{
            margin-top: 15px;
            font-size: 1.1em;
        }}
        
        .github-link {{
            color: #3498db;
            text-decoration: none;
            font-weight: bold;
            transition: color 0.3s ease;
        }}
        
        .github-link:hover {{
            color: #5dade2;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Advanced Web Enumeration Report</h1>
            <div class="subtitle">
                <strong>Target:</strong> {self.target_url}<br>
                <span>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
            </div>
        </div>

        <!-- Stats Overview -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{len(security_headers)}</div>
                <div class="stat-label">Security Headers</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len(subdomains)}</div>
                <div class="stat-label">Subdomains Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len(api_keys)}</div>
                <div class="stat-label">API Keys/Secrets</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len(sensitive_files)}</div>
                <div class="stat-label">Sensitive Files</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len(waf_detection)}</div>
                <div class="stat-label">WAFs Detected</div>
            </div>
        </div>

        <!-- Basic Info & WAF -->
        <div class="section">
            <h2>Basic Information & WAF Detection</h2>
            <div class="info-grid">
                <div class="info-card">
                    <h3>Response Details</h3>
                    <p><strong>Status Code:</strong> {self.results.get('status_code', 'N/A')}</p>
                    <p><strong>Response Time:</strong> {self.results.get('response_time', 'N/A')}s</p>
                    <p><strong>Final URL:</strong> {self.results.get('final_url', 'N/A')}</p>
                    <p><strong>Server:</strong> {self.results.get('headers', {}).get('Server', 'Unknown')}</p>
                </div>
                <div class="info-card {'critical' if not waf_detection else 'success'}">
                    <h3>WAF Detection Results</h3>
                    {''.join([f'<div class="vulnerability-item vulnerability-medium"><strong>{waf["name"]}</strong> - Confidence: {waf["confidence"]}%</div>' for waf in waf_detection]) if waf_detection else '<p>No WAF detected</p>'}
                </div>
            </div>
        </div>

        <!-- Technology Stack -->
        <div class="section">
            <h2>Technology Stack Analysis</h2>
            <div class="info-grid">
                <div class="info-card">
                    <h3>Stack Type: {self.results.get('stack_type', 'Unknown')}</h3>
                    <div class="tech-stack">
                        {' '.join([f'<span class="tech-badge">{tech}</span>' for tech in (tech_stack.get('frameworks', []) + tech_stack.get('cms', []) + tech_stack.get('javascript_libraries', []))])}
                    </div>
                </div>
            </div>
        </div>

        <!-- Security Headers -->
        <div class="section">
            <h2>Security Headers</h2>
            <div class="info-card">
                {''.join([f"<p><strong>{h}:</strong> {v}</p>" for h,v in security_headers.items()]) if security_headers else "<p>No security headers found</p>"}
            </div>
            <div class="info-card critical">
                <h3>Missing Critical Headers</h3>
                {''.join([f"<p>{h}</p>" for h in self.results.get("missing_critical_headers", [])]) or "<p>None missing</p>"}
            </div>
        </div>

        <!-- SSL/TLS -->
        <div class="section">
            <h2>SSL/TLS Analysis</h2>
            <div class="info-card">
                {''.join([f"<p><strong>{k}:</strong> {v}</p>" for k,v in ssl_info.items()]) if ssl_info else "<p>No SSL/TLS information available</p>"}
            </div>
        </div>

        <!-- WHOIS -->
        <div class="section">
            <h2>WHOIS Information</h2>
            <div class="info-card">
                {''.join([f"<p><strong>{k}:</strong> {v}</p>" for k,v in whois_info.items()]) if whois_info else "<p>No WHOIS information found</p>"}
            </div>
        </div>

        <!-- DNS -->
        <div class="section">
            <h2>DNS Records</h2>
            <div class="info-card">
                {''.join([f"<p>{rec}</p>" for rec in dns_records]) if dns_records else "<p>No DNS records found</p>"}
            </div>
        </div>

        <!-- CORS & Cookies -->
        <div class="section">
            <h2>CORS & Cookie Security</h2>
            <div class="info-card">
                {''.join([f"<p><strong>{k}:</strong> {v}</p>" for k,v in cors_cookies.items()]) if cors_cookies else "<p>No CORS or cookie issues detected</p>"}
            </div>
        </div>

        <!-- Subdomains -->
        <div class="section">
            <h2>Subdomains</h2>
            <div class="info-card">
                {''.join([f"<p>{sub}</p>" for sub in subdomains]) if subdomains else "<p>No subdomains found</p>"}
            </div>
        </div>

        <!-- API Keys -->
        <div class="section">
            <h2>API Keys / Secrets</h2>
            <div class="info-card critical">
                {''.join([f"<p><strong>{key['type']}:</strong> {key['location']}</p>" for key in api_keys]) if api_keys else "<p>No API keys leaked</p>"}
            </div>
        </div>

        <!-- Sensitive Files -->
        <div class="section">
            <h2>Sensitive Files</h2>
            <div class="info-card critical">
                {''.join([f"<p>{path} (Status: {info.get('status_code','N/A')})</p>" for path,info in sensitive_files.items()]) if sensitive_files else "<p>No sensitive files found</p>"}
            </div>
        </div>

        <!-- Robots.txt -->
        <div class="section">
            <h2>Robots.txt Analysis</h2>
            <div class="info-card">
                <p><strong>Raw Content:</strong></p>
                <pre>{self.results.get("robots_txt", "No robots.txt found")}</pre>
                <p><strong>Analysis:</strong></p>
                {''.join([f"<p>{rule}</p>" for rule in self.results.get("robots_analysis", [])]) or "<p>No sensitive entries</p>"}
            </div>
        </div>

        <!-- Plugins -->
        <div class="section">
            <h2>Plugins Detected</h2>
            <div class="info-card">
                {''.join([f"<p>{plugin}</p>" for plugin in plugins]) if plugins else "<p>No plugins detected</p>"}
            </div>
        </div>

        <!-- Versions -->
        <div class="section">
            <h2>Versions Detected</h2>
            <div class="info-card">
                {''.join([f"<p>{k}: {v}</p>" for k,v in versions.items()]) if versions else "<p>No version information detected</p>"}
            </div>
        </div>

        <!-- Footer -->
        <div class="footer">
            <div class="developer-info">
                InfoGather v2.0 - Developed by <a href="https://github.com/TENETx0" class="github-link">Monish Kanna</a>
            </div>
        </div>
    </div>
</body>
</html>
"""
        
        # Write the report to file
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"\n[+] Report saved to: {filename}")
        return filename


def display_banner():
    """Batman-themed Web Specter banner"""
    # ANSI colors
    GREEN = "\033[92m"   # neon green
    WHITE = "\033[97m"
    YELLOW = "\033[93m"
    PURPLE = "\033[95m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    bat_banner = f"""
N0xddddddddddddddddddddddd0WMMMMMMMMMMMMMMMMMMMMMMMMW0dddddddddddddddddddddddx0N
WXOdc'....................cKMMMMMMMMNXWMMWXNMMMMMMMMXc....................'cdOXW
MMMMWKx:..                .cKWMMMMMMOldxxdlkMMMMMMWKc.                 .:xKWMMMM
MMMMMMMW0c.                .':oxkOOOc. .. .cOOOkxoc'.                .c0WMMMMMMM
MMMMMMMMMWk'                    .....      .....                    'xNMMMMMMMMM
MMMMMMMMMMWx.                       TENETx0's                      .xWMMMMMMMMMM
MMMMMMMMMMMK;                                                      ;KMMMMMMMMMMM
MMMMMMMMMMMK; .......              WEB SPECTER             ....... ;KMMMMMMMMMMM
MMMMMMMMMMMNkxxxkxxxxddolc:,...                  ...,:cloddxxxkkxxxkXMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMWNXOxl;..          ..;lxOXNWMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMN0o,.      .,o0NMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWXd'.  .'dXWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWO;..;OWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM0oo0WMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWWWWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
                                                                                                                                     
    """

    subtitle = f"{CYAN}{BOLD}Uncover every corner of the web, effortlessly and intelligently{RESET}"
    github = f"{PURPLE}https://github.com/TENETx0/web-Specter{RESET}"
    
    q1= f'{RED}"Happy Hacking!"{RESET}'
    
    made_by = f"{WHITE}Made with ❤️  by Monish Kanna{RESET}"

    print(bat_banner)
    print(subtitle)
    print()
    print(f"GitHub: {github}")
    print()
    print(made_by)
    print()
    print(q1)
    print()



def main():
    """Main function"""
    display_banner()

    # Accept target from CLI or prompt interactively if not provided
    if len(sys.argv) >= 2 and sys.argv[1].strip():
        target_url = sys.argv[1].strip()
    else:
        try:
            target_url = input("\nEnter target URL (e.g. https://example.com) or press Enter to exit: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n\n[!] Input cancelled. Exiting.")
            sys.exit(0)

        if not target_url:
            print("\n[!] No target provided. Exiting.")
            sys.exit(0)

    print(f"\n[*] Starting advanced enumeration on: {target_url}")
    print("[*] This may take several minutes depending on the target.\n")

    try:
        # Initialize the enumerator
        enumerator = AdvancedWebEnumerator(target_url)

        # Run comprehensive analysis
        if enumerator.run_comprehensive_analysis():
            # Generate HTML report
            report_file = enumerator.generate_advanced_html_report()

            # Display summary
            print("\n" + "="*70)
            print("ENUMERATION SUMMARY")
            print("="*70)

            # Basic info
            print(f"\nTarget: {enumerator.target_url}")
            print(f"Status Code: {enumerator.results.get('status_code', 'N/A')}")
            print(f"Response Time: {enumerator.results.get('response_time', 'N/A')}s")

            # WAF Detection
            waf_detection = enumerator.results.get('waf_detection', [])
            if waf_detection:
                print(f"\nWAF Detected:")
                for waf in waf_detection:
                    print(f"  - {waf['name']} (Confidence: {waf['confidence']}%)")

            # Subdomains
            subdomains = enumerator.results.get('subdomains', [])
            print(f"\nSubdomains Found: {len(subdomains)}")

            # API Keys
            api_keys = enumerator.results.get('api_keys_leaked', [])
            if api_keys:
                print(f"\n[CRITICAL] API Keys/Secrets Found: {len(api_keys)}")
                for key in api_keys[:3]:  # Show first 3
                    print(f"  - {key['type']} in {key['location']}")

            # Sensitive Files
            sensitive_files = enumerator.results.get('sensitive_files', {})
            if sensitive_files:
                print(f"\nSensitive Files Found: {len(sensitive_files)}")
                for path, info in list(sensitive_files.items())[:5]:  # Show first 5
                    print(f"  - {path} (Status: {info.get('status_code', 'N/A')})")

            print(f"\n[+] Full report saved to: {report_file}")
            print("[+] Open the HTML file in your browser for detailed results.")

    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] An error occurred: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
