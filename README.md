<div align="center">
  <h1>Honeypot Dashboard</h1>
  <p>A Django-based honeypot project designed to simulate, monitor, and visualize malicious activity in a controlled environment, featuring a live-updating dashboard.</p>
  <img src="https://forthebadge.com/images/badges/made-with-python.svg">
  <img src="https://forthebadge.com/images/badges/built-with-love.svg">
  <br><br>
  <a href="https://github.com/SB2024-25/honeypot-dashboard/pulse">
    <img alt="Last commit" src="https://img.shields.io/github/last-commit/SB2024-25/honeypot-dashboard?style=for-the-badge&logo=starship&color=8bd5ca&logoColor=D9E0EE&labelColor=302D41" />
  </a>
  <a href="https://github.com/SB2024-25/honeypot-dashboard/stargazers">
    <img alt="Stars" src="https://img.shields.io/github/stars/SB2024-25/honeypot-dashboard?style=for-the-badge&logo=starship&color=c69ff5&logoColor=D9E0EE&labelColor=302D41" />
  </a>
  <a href="https://github.com/SB2024-25/honeypot-dashboard/issues">
    <img alt="Issues" src="https://img.shields.io/github/issues/SB2024-25/honeypot-dashboard?style=for-the-badge&logo=bilibili&color=F5E0DC&logoColor=D9E0EE&labelColor=302D41" />
  </a>
</div>

# Description
This honeypot project provides cybersecurity enthusiasts and professionals with a powerful tool to study attack patterns in a controlled environment. It simulates both network and web services to attract and log malicious activity, presenting the data on a dynamic, live-updating dashboard.

---

# Features

### Core Functionality
- **Database Backend:** All attack data is stored in a robust SQLite database, replacing fragile log files.
- **Live Attack Generation:** When a honeypot service is activated, a background process begins generating realistic, simulated attack data.
- **Dynamic Dashboard:** The dashboard automatically updates in real-time to show new attacks as they are generated, without needing a page refresh.
- **Data Visualization:** The dashboard includes aggregate statistics and a chart to visualize the distribution of different attack types.

### Web Honeypot
- **Web Logging:** Simulates a vulnerable website and records all HTTP requests, IP addresses, session details, and user agents.

### Network Honeypot
- **Network Logging:** Mimics network services like FTP and SSH to detect and log connection and authentication attempts.
- **Deceptive Environment:** Creates a deceptive environment to trap and analyze network-based attacks.

# Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/SB2024-25/honeypot-dashboard.git](https://github.com/SB2024-25/honeypot-dashboard.git)
    cd honeypot-dashboard
    ```

2.  **Set up the environment and install dependencies:**
    ```bash
    # Create and activate a virtual environment
    python -m venv venv
    .\venv\Scripts\activate
    
    # Install required packages
    pip install -r requirements.txt
    ```

3.  **Configure the database and admin user:**
    ```bash
    python manage.py migrate
    python manage.py createsuperuser
    ```
    *(You will need the admin user to log into the dashboard.)*

4.  **Start the honeypot dashboard:**
    ```bash
    python manage.py runserver
    ```
    Open the provided URL (e.g., `http://127.0.0.1:8000`) in your browser to access the dashboard.

# Technology Stack

- **Django:** A high-level Python Web framework for rapid development.
- **Flask:** A lightweight web application framework used for the web honeypot component.
- **paramiko:** A library for making SSH2 connections.
- **pyftpdlib:** A library for creating FTP servers.
- **Faker:** A library for generating fake data to simulate attacks.
- **ApexCharts.js:** A modern JavaScript charting library for data visualization.

# Usage
1.  Log in to the dashboard with the superuser account you created.
2.  Navigate to the `Setup` tab.
3.  Click the "Setup" button for either **Network** or **Website** to start the honeypot services.
4.  Once a service is started, the background attack generator will begin.
5.  Navigate back to the `Dashboard` to see the live attack feed and analysis.
6.  Navigate to the `Network`, `Website`, or `Keylogger` tabs to see filtered logs for those specific sources.

# Screenshots

*(Please add new screenshots of your updated dashboard here!)*

# Contributors

<a href="