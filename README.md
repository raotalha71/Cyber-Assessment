# 🛡️ Cyber Risk Assessment System

<div align="center">

![Python](https://img.shields.io/badge/Python-3.13-blue?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0.3-green?style=for-the-badge&logo=flask)
![Streamlit](https://img.shields.io/badge/Streamlit-1.40.0-red?style=for-the-badge&logo=streamlit)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

**A comprehensive cybersecurity risk assessment platform for SMEs with automated vulnerability scanning, ML-powered analysis, and business context-aware scoring.**

[Features](#-features) • [Installation](#-installation) • [Configuration](#-configuration) • [Usage](#-usage) • [Architecture](#-architecture) • [API Documentation](#-api-documentation)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [System Requirements](#-system-requirements)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Architecture](#-architecture)
- [API Documentation](#-api-documentation)
- [Database Schema](#-database-schema)
- [Machine Learning](#-machine-learning)
- [Security](#-security)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🌟 Overview

The **Cyber Risk Assessment System** is an enterprise-grade security assessment platform designed specifically for Small and Medium Enterprises (SMEs). It combines automated vulnerability scanning, manual security assessments, and machine learning-powered analysis to provide comprehensive security insights with business context awareness.

### 🎯 Key Highlights

- **Automated Vulnerability Scanning** using Nikto
- **ML-Enhanced Risk Analysis** with 12-feature extraction
- **Business Context Multipliers** (Industry, Data Sensitivity, IT Dependency)
- **OWASP Top 10 Mapping** with detailed explanations
- **PDF Report Generation** with comprehensive findings
- **User & Admin Dashboards** with role-based access control
- **TOTP-based 2FA** for enhanced security

---

## ✨ Features

### 🔍 **Automated Scanning**
- ✅ Nikto-based web vulnerability scanning
- ✅ Real-time scan progress tracking
- ✅ Configurable timeout and fast mode
- ✅ WSL/Docker/Linux multi-platform support

### 🤖 **Machine Learning Integration**
- ✅ 12-feature ML model for confidence prediction
- ✅ Scikit-learn Logistic Regression classifier
- ✅ Severity and confidence scoring
- ✅ Hybrid ML + rule-based analysis

### 📊 **Risk Scoring**
- ✅ Base score calculation from findings
- ✅ Business context multipliers
  - **Business Type**: Retail (1.0x), Finance (1.3x), Healthcare (1.4x), Education (1.1x)
  - **Data Sensitivity**: Low (1.0x), Medium (1.2x), High (1.5x)
  - **IT Dependency**: Low (1.0x), Medium (1.1x), High (1.3x)
- ✅ Normalized 0-100 risk scores
- ✅ 4-tier risk levels (Low/Medium/High/Critical)

### 📝 **Manual Assessment**
- ✅ 5-question security questionnaire
- ✅ Risk calculation with recommendations
- ✅ Category-based analysis

### 📄 **Reporting**
- ✅ Professional PDF report generation
- ✅ Comprehensive vulnerability details
- ✅ Risk-appropriate recommendations
- ✅ SME multiplier breakdown

### 👥 **User Management**
- ✅ User registration with TOTP 2FA
- ✅ Admin panel for user management
- ✅ Role-based access control
- ✅ Scan history tracking

---

## 💻 System Requirements

### **Minimum Requirements**

| Component | Requirement |
|-----------|-------------|
| **OS** | Windows 10/11, Linux, macOS |
| **Python** | 3.10 or higher (3.13 recommended) |
| **RAM** | 4GB minimum, 8GB recommended |
| **Disk Space** | 2GB for installation + scan storage |
| **WSL** | WSL2 with Ubuntu (Windows only) |
| **Nikto** | v2.1.5+ installed in WSL/Linux |

### **Software Dependencies**

- Python 3.10+
- pip (Python package manager)
- WSL2 with Ubuntu distribution (Windows)
- Nikto vulnerability scanner
- Virtual environment support

---

## 🚀 Installation

### **Step 1: Clone the Repository**

```bash
git clone <repository-url>
cd "cyber risk assessment (1)"
```

### **Step 2: Install Nikto (Required for Scanning)**

#### **On Windows (WSL2 Ubuntu)**

```bash
# Install WSL2 Ubuntu if not already installed
wsl --install -d Ubuntu

# Inside WSL Ubuntu terminal
wsl -d Ubuntu
sudo apt update
sudo apt install nikto -y
nikto -Version  # Verify installation
```

#### **On Linux**

```bash
sudo apt update
sudo apt install nikto -y
```

#### **On macOS**

```bash
brew install nikto
```

### **Step 3: Create Virtual Environment**

```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1

# Linux/macOS:
source .venv/bin/activate
```

### **Step 4: Install Python Dependencies**

```bash
# Install backend dependencies
cd backend
pip install -r requirements.txt

# Install frontend dependencies
cd ../ui
pip install -r requirements.txt
```

### **Step 5: Configure Environment Variables**

Create a `.env` file in the `backend` directory:

```bash
cd ../backend
```

**⚠️ IMPORTANT: Edit `.env` file with your settings:**

```env
FLASK_PORT=5050

# Nikto Configuration
NIKTO_TIMEOUT=90
NIKTO_MOCK_MODE=false
FORCE_WSL_NIKTO=true
NIKTO_FAST_MODE=true

# Database Path (optional - auto-creates in backend/)
# RISK_DB_PATH=./risk.db

# Reports Directory (optional - auto-creates)
# REPORTS_DIR=./reports
```

---

## ⚙️ Configuration

### **🔧 What You MUST Change**

1. **Nikto Path (WSL Users)**
   - If using Windows, ensure WSL Ubuntu is installed
   - Verify Nikto is accessible: `wsl -d Ubuntu nikto -Version`

2. **Database Location**
   - Default: `backend/risk.db` (auto-created)
   - To change: Set `RISK_DB_PATH` in `.env`

3. **Timeout Settings**
   - Adjust `NIKTO_TIMEOUT` in `.env` based on your network speed
   - Default: 90 seconds (increase for slower networks)

### **🎛️ Optional Configuration**

**Backend Settings** (`.env`):
- `NIKTO_MOCK_MODE=true` - Use mock scans for testing without Nikto
- `NIKTO_FAST_MODE=false` - Disable fast mode for thorough scans
- `FORCE_WSL_NIKTO=false` - Allow Docker fallback on Windows

**Frontend Settings**:
- Backend URL: `http://127.0.0.1:5050` (in `frontend_app.py` line 38)
- Timeout: 180 seconds (in `frontend_app.py` line 465)

---

## 🎮 Usage

### **Starting the Application**

**Terminal 1 - Backend:**
```bash
cd backend
.\.venv\Scripts\Activate.ps1  # Windows
# OR
source ../.venv/bin/activate  # Linux/macOS

python app.py
```

**Terminal 2 - Frontend:**
```bash
cd ui
.\.venv\Scripts\Activate.ps1  # Windows
# OR
source ../.venv/bin/activate  # Linux/macOS

streamlit run frontend_app.py
```

### **First-Time Setup**

1. **Access the Application**: Open browser to `http://localhost:8501`
2. **Register a User**:
   - Click "Register" tab
   - Fill in email, password, full name
   - Save the QR code and scan with authenticator app
   - Enter TOTP code to activate account
3. **Login**: Use email, password, and TOTP code

### **Running a Scan**

1. Navigate to **"🌐 Website Scan"**
2. Enter target URL (e.g., `http://testphp.vulnweb.com`)
3. Click **"Run Scan"**
4. View results in tabs:
   - **Overview**: Summary statistics
   - **Vulnerabilities**: Detailed findings
   - **AI Insights**: ML analysis
   - **Risk Analysis**: Risk metrics
   - **Raw Output**: Nikto raw results

### **Manual Assessment**

1. Navigate to **"📝 Manual Assessment"**
2. Answer 5 security questions
3. Click **"📊 Calculate Risk Score"**
4. View risk level and recommendations

### **Viewing History**

1. Navigate to **"📊 My History"**
2. View past scans with risk scores
3. Download PDF reports

---

## 🏗️ Architecture

### **System Architecture**

```
┌─────────────────────────────────────────────────────────────┐
│                     USER INTERFACE                          │
│              Streamlit Frontend (Port 8501)                 │
└────────────────────┬────────────────────────────────────────┘
                     │ HTTP/REST API
┌────────────────────▼────────────────────────────────────────┐
│                  BACKEND API LAYER                          │
│                Flask REST API (Port 5050)                   │
│  ┌──────────┬──────────┬──────────┬──────────────────────┐ │
│  │   Auth   │  Scan    │  Manual  │   Admin & Reports   │ │
│  │ Endpoint │ Endpoint │ Endpoint │      Endpoints      │ │
│  └──────────┴──────────┴──────────┴──────────────────────┘ │
└────────────────────┬────────────────────────────────────────┘
                     │
         ┌───────────┼───────────┐
         │           │           │
┌────────▼──────┐ ┌──▼─────┐ ┌──▼──────────┐
│   Database    │ │  Nikto │ │  ML Model   │
│   SQLite3     │ │ Scanner│ │ Scikit-     │
│               │ │  (WSL) │ │  Learn      │
└───────────────┘ └────────┘ └─────────────┘
```

### **Technology Stack**

| Layer | Technology | Purpose |
|-------|------------|---------|
| **Frontend** | Streamlit 1.40.0 | Interactive web UI |
| **Backend** | Flask 3.0.3 | REST API server |
| **Database** | SQLite3 | Data persistence |
| **Scanner** | Nikto 2.1.5+ | Vulnerability scanning |
| **ML** | Scikit-learn 1.8.0 | Risk prediction |
| **Security** | PyJWT, pyotp | Authentication & 2FA |
| **Reports** | ReportLab 4.2.2 | PDF generation |

---

## 📡 API Documentation

### **Authentication Endpoints**

#### `POST /auth/register`
Register a new user with TOTP setup.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123",
  "full_name": "John Doe"
}
```

**Response:**
```json
{
  "ok": true,
  "user_id": 1,
  "totp_secret": "BASE32SECRET",
  "qr_code_data": "data:image/png;base64,..."
}
```

#### `POST /auth/login`
Authenticate user and get session.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123"
}
```

### **Scan Endpoints**

#### `POST /scan/start`
Start a vulnerability scan.

**Request:**
```json
{
  "target": "http://example.com",
  "user_id": 1,
  "sme_id": 1
}
```

**Response:**
```json
{
  "ok": true,
  "scan_run_id": 123,
  "summary": {
    "total_findings": 5,
    "by_severity": {"High": 2, "Medium": 2, "Low": 1},
    "base_score": 45.2,
    "final_score": 62.5,
    "risk_level": "High"
  },
  "score": {
    "base_score": 45.2,
    "final_score": 62.5,
    "risk_level": "High",
    "business_type_multiplier": 1.3,
    "data_sensitivity_multiplier": 1.2,
    "it_dependency_multiplier": 1.1
  },
  "findings": [...]
}
```

#### `GET /user/history?user_id=1`
Get user's scan history.

### **Manual Assessment Endpoints**

#### `GET /manual/questions`
Get assessment questions.

#### `POST /manual/assess`
Submit manual assessment answers.

**Request:**
```json
{
  "user_id": 1,
  "sme_id": 1,
  "answers": [
    {"question_id": "asset_inventory", "answer": "Yes"},
    {"question_id": "access_control", "answer": "Partially"}
  ]
}
```

---

## 🗄️ Database Schema

### **Tables**

#### `users`
- `id` - Primary key
- `email` - Unique user email
- `password_hash` - Bcrypt hashed password
- `full_name` - User's full name
- `totp_secret` - TOTP secret for 2FA
- `is_active` - Account activation status
- `is_admin` - Admin role flag
- `created_at` - Registration timestamp

#### `smes`
- `id` - Primary key
- `name` - SME business name
- `industry` - Industry sector
- `size` - Company size
- `business_type` - Retail/Finance/Healthcare/Education/Other
- `data_sensitivity` - Low/Medium/High
- `it_dependency` - Low/Medium/High
- `website` - Company website
- `contact_email` - Contact email
- `created_at`, `updated_at` - Timestamps

#### `scan_runs`
- `id` - Primary key
- `sme_id` - Foreign key to smes
- `user_id` - Foreign key to users
- `target_url` - Scanned URL
- `summary_json` - JSON scan summary
- `base_score` - Score before multipliers
- `final_score` - Final 0-100 score
- `risk_level` - Low/Medium/High/Critical
- `business_type_multiplier` - Applied multiplier
- `data_sensitivity_multiplier` - Applied multiplier
- `it_dependency_multiplier` - Applied multiplier
- `created_at` - Scan timestamp

#### `scan_findings`
- `id` - Primary key
- `scan_run_id` - Foreign key to scan_runs
- `title` - Finding title
- `owasp_category` - OWASP Top 10 category
- `severity` - High/Medium/Low
- `confidence` - High/Medium/Low
- `uri` - Affected URI
- `raw_json` - Complete finding data

#### `manual_assessments`
- `id` - Primary key
- `sme_id` - Foreign key to smes
- `score_json` - JSON with answers and results
- `created_at` - Assessment timestamp

---

## 🤖 Machine Learning

### **Model Architecture**

- **Algorithm**: Logistic Regression (Scikit-learn)
- **Training**: Pre-trained on vulnerability dataset
- **Features**: 12-dimensional feature vector

### **Feature Extraction**

1. **Text Features**:
   - Text length
   - Word count
   
2. **Security Keywords**:
   - SQL, XSS, admin, outdated, directory, method, execute, shell, vulnerable
   
3. **Reference Indicators**:
   - CVE references
   - OSVDB references
   
4. **Severity Markers**:
   - Severity keywords (critical, high, severe, dangerous)
   - Info keywords (info, informational, notice)
   
5. **Technical Indicators**:
   - HTTP error codes (4xx, 5xx)
   - Version numbers
   - Path indicators
   - Header references
   - Exploit/attack keywords

### **Confidence Prediction**

Model outputs: **High**, **Medium**, or **Low** confidence
- Falls back to rule-based scoring if ML fails

---

## 🔒 Security

### **Authentication**
- Bcrypt password hashing
- TOTP-based 2FA (compatible with Google Authenticator, Authy)
- JWT tokens for session management

### **Authorization**
- Role-based access control (User/Admin)
- User-specific data isolation

### **Best Practices**
- Environment variable configuration
- SQL injection prevention (parameterized queries)
- CORS protection
- Input validation

---

## 🐛 Troubleshooting

### **Common Issues**

#### ❌ **"Connection lost to backend"**
- **Cause**: Scan timeout or backend crash
- **Solution**: 
  - Increase `NIKTO_TIMEOUT` in `.env`
  - Use simpler target URLs
  - Check if Nikto is installed: `wsl -d Ubuntu nikto -Version`

#### ❌ **"Nikto not found"**
- **Cause**: Nikto not installed or WSL not configured
- **Solution**:
  - Windows: `wsl -d Ubuntu sudo apt install nikto -y`
  - Linux: `sudo apt install nikto -y`
  - Verify: `wsl -d Ubuntu nikto -Version`

#### ❌ **"Module not found" errors**
- **Cause**: Missing Python packages
- **Solution**:
  - Activate virtual environment
  - `pip install -r backend/requirements.txt`
  - `pip install -r ui/requirements.txt`

#### ❌ **"Port already in use"**
- **Cause**: Backend/Frontend already running
- **Solution**:
  - Kill processes: `Stop-Process -Name python -Force`
  - Restart application

#### ❌ **"TypeError: save_scan_run() takes X arguments"**
- **Cause**: Bytecode cache issue
- **Solution**:
  - Delete `__pycache__` folders
  - Restart backend: `python -B app.py`

---

## 📁 Project Structure

```
cyber risk assessment (1)/
├── README.md                     # This file
├── .venv/                        # Virtual environment
├── backend/
│   ├── app.py                    # Flask API server
│   ├── requirements.txt          # Backend dependencies
│   ├── .env                      # Configuration (create this)
│   ├── auth_db.py                # User authentication
│   ├── db_helpers.py             # Database operations
│   ├── nikto_runner.py           # Nikto scan execution
│   ├── pdf_report.py             # PDF generation
│   ├── totp_utils.py             # 2FA utilities
│   ├── manual/
│   │   ├── manual_questions.py   # Assessment questions
│   │   └── manual_scoring.py     # Risk calculation
│   ├── ml/
│   │   ├── feature_extractor.py  # ML features
│   │   ├── predictor.py          # ML predictions
│   │   └── train_model.py        # Model training
│   ├── scan/
│   │   ├── owasp_map.py          # OWASP mapping
│   │   ├── scan_scoring.py       # Score calculation
│   │   └── vuln_explain.py       # Vulnerability explanations
│   └── reports/                  # Nikto scan outputs
├── ui/
│   ├── frontend_app.py           # Streamlit UI
│   └── requirements.txt          # Frontend dependencies
└── risk.db                       # SQLite database (auto-created)
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 👨‍💻 Author

**Your Name**  
📧 Email: your.email@example.com  
🔗 LinkedIn: [Your LinkedIn](https://linkedin.com/in/yourprofile)  
🐙 GitHub: [Your GitHub](https://github.com/yourusername)

---

## 🙏 Acknowledgments

- **Nikto** - Open-source web vulnerability scanner
- **OWASP** - Top 10 vulnerability framework
- **Streamlit** - Interactive web framework
- **Flask** - Lightweight web framework
- **Scikit-learn** - Machine learning library

---

<div align="center">

**⭐ Star this repository if you find it useful!**

Made with ❤️ for SME cybersecurity

</div>
