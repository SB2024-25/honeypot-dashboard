# Honeypot Dashboard (AI-Powered Security Monitoring)

<div align="center">
  <p>A comprehensive cybersecurity monitoring platform built with Django that simulates, visualizes, and analyzes network and web-based cyber attacks in real-time, powered by local Ollama AI for intelligent security analysis.</p>
  <img src="https://forthebadge.com/images/badges/made-with-python.svg" alt="Made with Python">
  <img src="https://forthebadge.com/images/badges/built-with-love.svg" alt="Built with Love">
  <img src="https://img.shields.io/badge/AI-Ollama-FF6B6B" alt="Ollama AI">
</div>

## 🚀 Project Overview

This advanced honeypot monitoring system simulates a Security Operations Center (SOC) dashboard, providing real-time visualization and AI-powered analysis of simulated cyber attacks. It features multiple honeypot services, intelligent attack generation, and professional security analytics - all powered by free, local AI for unlimited analysis.

---

## ✨ Key Features

* **🔄 Live Security Dashboard**: Real-time updates for attack logs, interactive world map, live statistics (total attacks, unique IPs), and dynamic charts (attack types, source distribution) without page refreshes
* **🤖 Local AI-Powered Analysis**: Integrated Ollama AI provides free, unlimited security analysis with professional cybersecurity insights and recommendations
* **🎯 Intelligent Attack Simulation**: Context-aware attack generation with follow-up scenarios (Brute Force after Port Scans, SQLi after Reconnaissance)
* **🌍 Interactive Attack Map**: Live geolocation mapping using Leaflet.js and GeoLite2 database to visualize global attack patterns
* **📊 Professional Analytics**: Multiple honeypot services (Network SSH/FTP, Web Application, Keylogger) with individual monitoring views
* **🔒 Export-Ready Reports**: Generate and download professional security analysis reports in HTML format
* **⚡ Service Control Panel**: Easy start/stop controls for all honeypot simulations with automatic attack generation
* **🔐 Secure Authentication**: Django-powered user management with session-based security

---

## 🛠 Prerequisites

Ensure you have the following installed on your system:

* **Python**: Version 3.8 or newer
* **Git**: For cloning the repository
* **Ollama**: Local AI engine for free analysis ([Installation Guide](#ollama-setup))
* **GeoLite2 City Database**: Download the free `GeoLite2-City.mmdb` from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)

---

## ⚡ Quick Installation & Setup

### 1. Clone & Setup Environment
```bash
git clone https://github.com/your-username/honeypot-dashboard.git
cd honeypot-dashboard

# Create virtual environment
python -m venv venv

# Activate environment
# Windows:
.\venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Ollama Setup (Free AI Analysis)
```bash
# Install Ollama system-wide (run in separate terminal)
curl -fsSL https://ollama.ai/install.sh | sh

# Download AI model (choose one)
ollama pull llama3.2:3b    # Fast & lightweight (recommended)
# OR
ollama pull phi3:mini      # Ultra-lightweight
# OR
ollama pull llama3.1:8b    # More capable

# Install Python client in your virtual environment
pip install ollama
```

### 3. GeoIP Database Setup
```bash
# Create directory and place GeoLite2 database
mkdir geoip_data
# Download GeoLite2-City.mmdb from MaxMind and place in geoip_data/
```

### 4. Database & Superuser Setup
```bash
# Setup database
python manage.py migrate

# Create admin user (follow prompts)
python manage.py createsuperuser
# Username: admin
# Email: (optional)
# Password: (choose secure password)
```

### 5. Optional: Environment Configuration
Create `.env` file for additional configurations:
```dotenv
# Optional: For future external AI services
GOOGLE_API_KEY=your_google_api_key_optional
```

---

## 🚀 Running the Application

### Start the Dashboard
```bash
# Activate virtual environment
.\venv\Scripts\activate  # Windows
source venv/bin/activate # macOS/Linux

# Start Django server
python manage.py runserver
```

### Access the Dashboard
1. Open browser to: `http://127.0.0.1:8000/`
2. Login with your superuser credentials
3. Navigate to **Setup** page to start honeypot services

### Start Honeypot Services
1. Go to **Setup** page via sidebar
2. Click "Start" for **Network** (SSH/FTP) or **Website** services
3. AI attack generator will automatically begin simulating attacks
4. Return to **Dashboard** to view live monitoring

### AI Analysis Features
- **Dashboard AI Button**: Quick security analysis in modal
- **Analyze Page**: Detailed security reports with export functionality
- **Automatic Updates**: Real-time analysis as new attacks occur

### Stop Application
```bash
# Press Ctrl+C in the terminal running runserver
# Services automatically stop when server shuts down
```

---

## 🏗 Project Structure

```
honeypot-dashboard/
├── attack_simulator/          # Core application
│   ├── models.py             # AttackLog database model
│   ├── views.py              # All views & AI integration
│   └── urls.py               # URL routing
├── templates/                 # Frontend templates
│   ├── base.html             # Base template
│   ├── dashboard.html        # Main dashboard with AI modal
│   ├── analyze.html          # Analysis page with export
│   └── setup.html            # Service control panel
├── honeypot/                 # Honeypot service implementations
│   └── Honeypot_Project_final/
├── geoip_data/               # GeoLocation database
│   └── GeoLite2-City.mmdb
├── static/                   # CSS, JS, images
├── db.sqlite3               # Database (auto-generated)
└── manage.py                # Django management
```

---

## 🛡 Technology Stack

* **Backend Framework**: Python, Django
* **AI Engine**: Ollama (local), various LLM models
* **Honeypot Services**: Flask, Paramiko, pyftpdlib
* **Database**: SQLite (Django ORM)
* **Geolocation**: geoip2, MaxMind GeoLite2
* **Frontend**: HTML5, Tailwind CSS, JavaScript
* **Visualization**: ApexCharts.js, Leaflet.js
* **Real-time Updates**: AJAX, Django Channels
* **Security**: Django Authentication, CSRF Protection

---

## 📊 Features Deep Dive

### 🤖 AI-Powered Security Analysis
- **Free & Unlimited**: No API costs with local Ollama
- **Professional Reports**: Structured cybersecurity analysis
- **Real-time Insights**: Live analysis of attack patterns
- **Actionable Recommendations**: Specific security measures

### 🎯 Attack Simulation
- **Multiple Vectors**: SQLi, XSS, Brute Force, Port Scanning, DDoS
- **Realistic Scenarios**: Multi-stage attack sequences
- **Geolocated IPs**: Global attack distribution
- **Service-Specific**: Targeted attacks for each honeypot type

### 📈 Visualization & Analytics
- **Live World Map**: Real-time attack geolocation
- **Interactive Charts**: Attack type and source distribution
- **Real-time Tables**: Live activity feed
- **Export Capabilities**: Professional report generation

---

## 🐛 Troubleshooting

### Common Issues & Solutions

**Ollama Connection Failed:**
```bash
# Ensure Ollama service is running
ollama serve
# Test connection
python -c "import ollama; print(ollama.generate('llama3.2:3b', 'test')['response'])"
```

**GeoIP Database Missing:**
- Download from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
- Place in `geoip_data/GeoLite2-City.mmdb`

**Port Already in Use:**
```bash
# Use different port
python manage.py runserver 8001
```

**Database Issues:**
```bash
# Reset if needed
python manage.py migrate --run-syncdb
```

---

## 🔧 Development

### Adding New Features
1. Create new branch: `git checkout -b feature/new-feature`
2. Make changes and test
3. Commit: `git commit -m "feat: description"`
4. Push: `git push origin feature/new-feature`

### Project Extensions
- Add more honeypot services
- Integrate additional AI models
- Enhance visualization components
- Add alerting system
- Implement user roles

---

## 📸 Screenshots

<img width="1916" height="874" alt="Screenshot 2025-10-26 223855" src="https://github.com/user-attachments/assets/6ec33d7e-a82c-44da-9782-00d3449b44e1" />

---

## 👥 Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🎉 Acknowledgments

* **Ollama** for providing free, local AI capabilities
* **MaxMind** for GeoLite2 geolocation data
* **Django** community for excellent documentation
* **Tailwind CSS** for beautiful, responsive design

---

<div align="center">

**⭐ Star this repo if you found it helpful!**

*For questions or support, open an issue on GitHub.*

</div>
