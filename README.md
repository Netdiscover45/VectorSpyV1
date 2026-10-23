# 🛡️ VectorSpy
### Automated Cybersecurity Assessment & Risk Visualization Platform

**VectorSpy** is a Python and Flask-based cybersecurity assessment platform designed to simplify authorized security testing through a centralized web interface. It integrates network reconnaissance, web security configuration checks, technology fingerprinting, rule-based risk classification, findings management, and scan history into a unified dashboard.

Developed as an academic mini project, VectorSpy demonstrates the practical application of cybersecurity concepts, web application development, and security assessment workflows.

<p align="center">
  <strong>Discover • Assess • Analyze • Visualize • Improve</strong>
</p>

---

## 📌 Project Information

| Attribute | Details |
|---|---|
| Project Name | VectorSpy |
| Project Type | Academic Mini Project |
| Current Version | V1 |
| Development Status | Active Development |
| Programming Language | Python |
| Web Framework | Flask |
| Database | SQLite |
| Network Scanning | Nmap |
| Supported Environments | Windows / Kali Linux |
| Frontend | HTML, CSS, JavaScript |

## 📖 1. Project Overview

VectorSpy provides a centralized interface for performing basic, authorized cybersecurity assessments and organizing the results in an accessible format.

The V1 implementation includes three core assessment modules:

- **Network Security Assessment:** Identifies open ports, services, and service versions using Nmap.
- **Web Security Assessment:** Evaluates selected HTTP security headers, cookie attributes, server information, and other basic web security configurations.
- **Technology Finder:** Detects identifiable technologies associated with websites, such as web servers, content management systems, frontend frameworks, and other supported technologies.

Assessment results are processed through a configurable, rule-based risk engine. Findings, severity levels, risk scores, evidence, and recommendations are stored in an SQLite database and displayed through the web dashboard.

> **Scope:** VectorSpy V1 focuses on basic security assessment and configuration analysis. It is not a replacement for a professional penetration-testing suite or a comprehensive vulnerability scanner.

## 🎯 2. Project Objectives

The primary objectives of VectorSpy are to:

- Develop a centralized web-based cybersecurity assessment interface.
- Perform network reconnaissance and service identification using Nmap.
- Evaluate selected web security configurations.
- Identify supported web technologies and frameworks.
- Classify detected issues using predefined security rules.
- Generate risk indicators and actionable security recommendations.
- Store assessment results and findings in a local database.
- Maintain scan history and provide dashboard-level statistics.
- Demonstrate the integration of Python, Flask, networking tools, and database management in a practical cybersecurity project.

## 🚀 3. Key Features

### 🔐 Authentication and Access Control

- User registration and login.
- Password hashing.
- Session-based authentication.
- Protected dashboard and assessment routes.

### 🌐 Network Security Assessment

- Nmap-based network scanning.
- Open port identification.
- Service and service-version detection.
- Rule-based risk classification.
- Findings and recommendation generation.
- Scan-result storage.
- Invalid-target and error handling.

### 🔎 Web Security Assessment

The module checks selected web security configurations, including:

- `Content-Security-Policy`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Strict-Transport-Security` (HSTS)
- `Referrer-Policy`
- `Permissions-Policy`
- Cookie security attributes
- Server and `X-Powered-By` information
- HTTP methods
- `Cache-Control`
- `Content-Type`

The results help identify potentially missing or weak configurations. A missing header does not automatically prove that a website is vulnerable; findings must be interpreted in the context of the application.

### 🧩 Technology Finder

Identifies detectable web technologies, including:

- Web servers
- Programming languages
- Content management systems (CMS)
- JavaScript frameworks
- Frontend libraries
- Content delivery networks (CDNs)
- Analytics technologies
- Other supported web technology indicators

Detection accuracy depends on the information exposed by the target website.

### ⚠️ Rule-Based Risk Detection

The risk engine evaluates findings against configured rules and assigns supported severity levels:

- **Low**
- **Medium**
- **High**

Depending on the applicable rule, the platform records a risk score, supporting evidence, and a recommended remediation step.

These classifications are preliminary indicators and should not be interpreted as a formal industry-standard risk rating unless a documented scoring methodology is implemented.

### 📊 Security Dashboard

The dashboard provides a centralized view of:

- Assessment statistics.
- Recent scans.
- Risk and severity information.
- Available assessment modules.
- Findings and scan history.
- Navigation to network and web assessment tools.

### 📋 Findings Management

Stored findings can include:

- Assessment source.
- Target.
- Finding title or description.
- Severity and risk score.
- Supporting evidence.
- Recommended remediation.
- Date and time.

### 🕒 Scan History

- Stores assessment identifiers and targets.
- Records scan types and timestamps.
- Tracks available completion statuses.
- Provides access to historical results.
- Supports deletion of completed scan records and their associated findings.

### 🖥️ User Interface

- Welcome, login, and registration pages.
- Application loading screen.
- Dashboard with assessment statistics.
- Scan progress interface.
- Responsive page styling.
- Module status indicators.
- Labels for planned V2 functionality.

## 🏗️ 4. System Architecture

VectorSpy follows a modular architecture in which the Flask application connects the user interface, assessment modules, risk engine, and database.

```text
                         USER
                           |
                           v
                 Authentication Layer
                           |
                           v
                       Dashboard
                           |
             +-------------+-------------+
             |             |             |
             v             v             v
       Network Scan   Web Assessment  Technology
          (Nmap)       (HTTP Checks)    Finder
             |             |             |
             +-------------+-------------+
                           |
                           v
                 Rule-Based Risk Engine
                           |
                           v
                     SQLite Database
                           |
             +-------------+-------------+
             |             |             |
             v             v             v
          Findings     Scan History   Dashboard
                                      Statistics
```

### Architecture Components

| Component | Responsibility |
|---|---|
| Flask Application | Routing, application logic, and request handling |
| Authentication Layer | Registration, login, sessions, and route protection |
| Network Scanner | Nmap-based network and service discovery |
| Web Scanner | Selected HTTP and web security configuration checks |
| Technology Finder | Website technology identification |
| Risk Engine | Rule-based severity classification and recommendations |
| Database Layer | Persistence of users, scans, findings, and related data |
| Frontend | Dashboard, assessment forms, results, and history views |

## 🛠️ 5. Technology Stack

| Category | Technology |
|---|---|
| Language | Python 3 |
| Backend Framework | Flask |
| Network Assessment | Nmap |
| Web Assessment | Python HTTP and response analysis |
| Technology Detection | Python-based detection logic |
| Risk Analysis | Custom rule-based engine |
| Database | SQLite |
| Frontend | HTML5, CSS3, JavaScript |
| Authentication | Flask sessions and password hashing |
| Code Editor | Visual Studio Code |
| Operating Systems | Windows and Kali Linux |
| Version Control | Git and GitHub |

## 📁 6. Project Structure

```text
VectorSpy/
│
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── templates/
│   ├── base.html
│   ├── loading.html
│   ├── welcome.html
│   ├── login.html
│   ├── signup.html
│   ├── dashboard.html
│   ├── network_scan.html
│   ├── scan_results.html
│   ├── technology_finder.html
│   ├── web_security.html
│   ├── findings.html
│   └── scan_history.html
│
├── static/
│   ├── css/
│   │   └── style.css
│   ├── js/
│   │   └── loading.js
│   └── images/
│       └── VectorSpy-logo.png
│
├── scanners/
│   ├── nmap_scanner.py
│   ├── technology_finder.py
│   └── web_scanner.py
│
├── core/
│   └── risk_engine.py
│
└── database/
    └── db.py
```

*This structure represents the documented project layout. Adjust filenames if your actual repository differs.*

## 💻 7. Requirements

Before running VectorSpy, install:

- Python 3.
- Git.
- Nmap.
- pip.
- Visual Studio Code (recommended).
- A Python virtual environment.

The Python packages required by the application are listed in `requirements.txt`.

## ⚙️ 8. Installation and Setup

### Windows

**Step 1 — Verify installations**

```powershell
python --version
git --version
nmap --version
```

Install Nmap and Npcap if they are not already available.

**Step 2 — Clone the repository**

```powershell
git clone https://github.com/USERNAME/VectorSpy.git
cd VectorSpy
```

Replace `USERNAME` with the actual GitHub username and repository URL.

**Step 3 — Create and activate a virtual environment**

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, use the following command for the current terminal session and try again:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1
```

**Step 4 — Install dependencies**

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

**Step 5 — Start the application**

```powershell
python app.py
```

Open the following address in your browser:

`http://127.0.0.1:5000`

### Kali Linux

**Step 1 — Install system dependencies**

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv git nmap -y
```

**Step 2 — Clone the repository**

```bash
git clone https://github.com/USERNAME/VectorSpy.git
cd VectorSpy
```

**Step 3 — Create and activate a virtual environment**

```bash
python3 -m venv venv
source venv/bin/activate
```

**Step 4 — Install Python dependencies**

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

**Step 5 — Run VectorSpy**

```bash
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

To stop the development server, press `Ctrl + C`.

> **Troubleshooting:** If the application cannot locate Nmap, verify that Nmap is installed and available in the system PATH. If dependency installation fails, check the Python version and package requirements.

## ▶️ 9. Running VectorSpy

After completing installation:

1. Open the VectorSpy project directory.
2. Activate the virtual environment.
3. Confirm that the required dependencies and Nmap are available.
4. Run `python app.py` on Windows or Kali Linux.
5. Open `http://127.0.0.1:5000`.
6. Register or log in and navigate to the available assessment modules.
7. Run assessments only against authorized targets.

Use the Flask development server for local development and academic demonstrations. Additional deployment hardening is required before exposing the application to other users or networks.

## ✅ 10. V1 Implementation Status

The following table reflects the implementation status documented for the current project version. Verify each item against the actual code before publishing a release.

| Module / Feature | Reported Status |
|---|---|
| Welcome and Loading Pages | Implemented |
| User Registration and Login | Implemented |
| Session-Based Access Control | Implemented |
| Security Dashboard | Implemented |
| Network Scanning | Implemented |
| Nmap Service Detection | Implemented |
| Service Version Detection | Implemented |
| Network Risk Classification | Implemented |
| Web Security Checks | Implemented |
| Technology Finder | Implemented |
| Technology Risk Classification | Implemented |
| Findings Management | Implemented |
| Security Recommendations | Implemented |
| Scan History | Implemented |
| Scan Deletion | Implemented |
| SQLite Storage | Implemented |

## 🗄️ 11. Database Design

VectorSpy uses SQLite for local persistence.

The documented database entities include:

- **Users:** Account and authentication-related data.
- **Scans:** Assessment targets, types, timestamps, and statuses.
- **Findings:** Detected issues, severity, evidence, and recommendations.
- **Technologies:** Detected technology information and related risk data.

The application initializes its database through the database module.

Default database filename: `vectorspy.db`

### Database Protection

Local databases may contain usernames, assessment targets, findings, and other sensitive information. Do not commit a real database to a public repository.

Recommended `.gitignore` entries:

```gitignore
*.db
*.sqlite
*.sqlite3
venv/
.venv/
__pycache__/
.env
.vscode/
```

## 🧪 12. Testing and Validation

Testing should verify that each assessment module produces expected results and handles failures safely.

### Authentication Testing

- Registration with valid and invalid inputs.
- Login with correct and incorrect credentials.
- Session handling and logout.
- Access to protected routes.

### Network Assessment Testing

- Authorized target scanning.
- Open-port identification.
- Service and version detection.
- Invalid target handling.
- Nmap execution errors.
- Risk classification and finding storage.

### Web Security Testing

- HTTP response and header inspection.
- Cookie attribute evaluation.
- HTTPS and HSTS configuration checks.
- HTTP method handling.
- Invalid URL and connection error handling.

### Technology Finder Testing

- Detection of supported technology indicators.
- Handling of unavailable or incomplete responses.
- Technology version detection where evidence is available.
- Risk classification and result storage.

### Database Testing

- Scan record creation.
- Finding and technology storage.
- Scan history retrieval.
- Deletion of scans and associated findings.
- Handling of missing or invalid records.

For an academic demonstration, record test inputs, expected outputs, actual results, and any known limitations. Use a local lab or explicitly authorized targets.

## 🔮 13. Future Scope — V2

The following features are planned for future development and are **not claimed as completed V1 functionality**.

- OWASP ZAP integration.
- Nikto integration.
- Nuclei integration.
- Expanded web vulnerability assessment.
- TLS/SSL configuration assessment.
- Linux security auditing.
- Windows security auditing.
- Advanced risk analysis and finding correlation.
- Scan comparison and trend analysis.
- PDF security reports.
- Data export and advanced visualizations.
- Improved vulnerability intelligence integration.

These enhancements would extend the platform's assessment capabilities and improve the presentation of security findings.

## ⚖️ 14. Security and Legal Disclaimer

VectorSpy is intended for educational use, authorized security assessment, and controlled laboratory testing.

- Scan only systems, networks, and websites for which you have explicit permission.
- Follow applicable laws, organizational policies, and service terms.
- Do not use the application to access, disrupt, or test third-party systems without authorization.
- Treat scan results as assessment indicators that may require manual verification.
- Protect credentials, session data, databases, and collected assessment results.

The project is an academic tool and does not guarantee the detection of every vulnerability or the security of an assessed system.

## 🎓 15. Academic Purpose and Learning Outcomes

VectorSpy demonstrates the practical integration of:

- Network reconnaissance and service identification.
- HTTP security configuration analysis.
- Web technology fingerprinting.
- Rule-based risk classification.
- Python and Flask application development.
- Authentication and session management.
- SQLite database operations.
- Security findings management.
- Dashboard development and assessment workflows.

The project provides a foundation for exploring more advanced security assessment techniques and secure software development practices.

## 📌 16. Project Status

**Version:** V1  
**Status:** Active Development  
**Platform:** Windows / Kali Linux  
**Purpose:** Academic Cybersecurity Mini Project

VectorSpy V1 establishes a modular workflow for basic cybersecurity assessment, risk classification, and findings management. Future versions may expand the platform through additional assessment integrations and reporting capabilities.

## 📄 17. License

This project is developed for academic and educational purposes.

A formal open-source license has not been specified. If you plan to publish the repository publicly, consider selecting an appropriate license and adding a `LICENSE` file.

---

**VectorSpy — A Practical Approach to Cybersecurity Assessment and Risk Visibility.**
