# 🕷️ WebSpecter

![WebSpecter Banner](https://img.shields.io/badge/WebSpecter-v1.0-brightgreen)
![Python](https://img.shields.io/badge/Python-3.8+-blue)
![License](https://img.shields.io/badge/License-MIT-orange)

**WebSpecter** is a **powerful web information gathering tool** designed for cybersecurity enthusiasts, pentesters, and researchers. It provides **smart technology detection, security analysis, SSL inspection, WHOIS lookup, plugin detection, and professional HTML reports** — all from a simple Python CLI tool.

GitHub Repository: [https://github.com/TENETx0/web-Specter](https://github.com/TENETx0/web-Specter)

---

## ✨ Features

### **Core Features**
- **Command Line Usage:** `python3 infogather.py`
- **URL Input:** Prompts for website URL (e.g., `https://www.example.com/`)
- **Loading Progress:** Animated loader similar to `nmap -v`
- **Technology Detection:** Detects MEAN/MERN/LAMP stacks, frameworks, and databases
- **HTML Report Generation:** Creates **detailed, professional, interactive reports**

### **Advanced Features**
1. **Security Headers Analysis:** Checks 25+ headers including CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy, and more.
2. **SSL Certificate Inspection:** Extracts full certificate info, protocol, cipher suite, fingerprints, and expiration alerts.
3. **WHOIS Domain Information:** Provides registration details, expiry, DNS info, and geographic data.
4. **Common Path Discovery:** Checks admin panels, config files, API endpoints, backup files, and development directories.
5. **CMS & Plugin Detection:** Detects WordPress, Drupal, Joomla, Magento plugins, JS libraries, server software, and framework versions.

---

## 🔍 Technology Detection

**Frontend:** React, Angular, Vue, Ember, Backbone, Knockout, Meteor, Svelte  
**CSS Frameworks:** Bootstrap, Foundation, Bulma, Materialize, Semantic-UI, Tailwind  
**Backend:** Django, Flask, Laravel, Symfony, CodeIgniter, CakePHP, Rails, Spring, ASP.NET, FastAPI, NestJS  
**CMS:** WordPress, Drupal, Joomla, Magento, Shopify, Ghost, TYPO3, Concrete5, Umbraco  
**Modern Stacks:** Next.js, Nuxt, Gatsby, Webpack, Parcel, Rollup  

---

## 🗄️ Database Detection

MySQL, PostgreSQL, MongoDB, Redis, SQLite, Oracle, MSSQL, Cassandra  
Elasticsearch, Neo4j, CouchDB, Firebase, DynamoDB, InfluxDB, MariaDB  

---

## 🛡️ Security Headers (25+)

- **Core:** CSP, HSTS, X-Frame-Options, X-XSS-Protection, Referrer-Policy  
- **Modern:** Permissions-Policy, Cross-Origin-Embedder-Policy, Expect-CT  
- **Cache & Proxy:** Cache-Control, Via, X-Cache, X-Served-By  
- **Application:** X-Rate-Limit, X-Request-ID, X-Correlation-ID  

---

## 🔒 SSL/TLS Certificate Analysis

- Complete Certificate Details: Subject, Issuer, Serial Number, Key Size  
- Security Info: Protocol version, Cipher suite, Certificate Authority type  
- Fingerprints: SHA256, SHA1, MD5  
- Validity Checks: Expiration dates, days until expiry, security warnings  
- Subject Alternative Names: All domains covered by the certificate  

---

## 📝 HTML Report Features

- **Interactive Design:** Collapsible sections, hover effects, animated header  
- **Statistics Dashboard:** Key metrics visualized in cards  
- **Color-Coded Status:** HTTP codes differentiated by colors  
- **Responsive Layout:** Works on desktop and mobile  
- **Professional Styling:** Gradient backgrounds, shadows, modern typography  

---

## ⚡ Usage

```bash
git clone https://github.com/TENETx0/web-Specter.git
cd web-Specter
python3 infogather.py
