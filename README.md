# Honeypot Dashboard (AI-Powered Simulation)

<div align="center">
  <p>A dynamic web application built with Django that simulates and visualizes network and web-based cyber attacks in real-time, powered by Perplexity AI for realistic event generation.</p>
  <img src="https://forthebadge.com/images/badges/made-with-python.svg" alt="Made with Python">
  <img src="https://forthebadge.com/images/badges/built-with-love.svg" alt="Built with Love">
</div>

## Project Overview

This project simulates a security operations center (SOC) dashboard, providing a live feed and analysis of simulated cyber attacks. It features honeypot services for Network (SSH/FTP) and Web targets. Attack events are generated dynamically by the Perplexity AI, geolocated, and displayed on an interactive map and updating charts, offering a compelling visualization of security events.

---

## Key Features

* **Live Dashboard:** Real-time updates for attack logs, map markers, statistics (total attacks, unique IPs), and charts (attack type, source distribution) without requiring page refreshes. 📊
* **AI-Powered Attack Generation:** Utilizes the Perplexity AI API to generate a continuous stream of diverse and contextually relevant simulated attacks (Brute Force, SQLi, XSS, Port Scans, Recon, etc.) when honeypot services are active. 🤖
* **Honeypot Service Simulation:** Includes background services mimicking Network (SSH/FTP via Paramiko/pyftpdlib) and Web (via Flask) targets.
* **Interactive Attack Map:** Uses Leaflet.js and a GeoLite2 database to plot incoming attacks on a world map based on IP address geolocation. 🗺️
* **Scenario Simulation:** Basic logic to generate follow-up attacks (e.g., Brute Force after a Port Scan) from the same IP address.
* **Database Logging:** All simulated attacks are stored reliably in an SQLite database (`db.sqlite3`) managed by Django's ORM.
* **Service Control Panel:** Simple UI to start/stop the honeypot simulation services.
* **User Authentication:** Secured by Django's built-in user login system.

---

## Prerequisites

Ensure you have the following installed on your system:

* **Python:** Version 3.8 or newer.
* **Git:** For cloning the repository.
* **GeoLite2 City Database:** Download the free `GeoLite2-City.mmdb` file from MaxMind ([Instructions](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)) and place it in a `geoip_data` folder within the project root.
* **Perplexity AI API Key:** Obtain an API key from Perplexity AI ([https://perplexity.ai/](https://perplexity.ai/)).

---

## Installation & Setup

Follow these commands in your terminal:

1.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/SB2024-25/honeypot-dashboard.git](https://github.com/SB2024-25/honeypot-dashboard.git)
    cd honeypot-dashboard
    ```

2.  **Create & Activate Virtual Environment:**
    ```bash
    python -m venv venv
    .\venv\Scripts\activate
    ```
    *(On macOS/Linux, use `source venv/bin/activate`)*

3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
   

4.  **Place GeoIP Database:**
    * Create a folder named `geoip_data` in the project root (where `manage.py` is).
    * Place your downloaded `GeoLite2-City.mmdb` file inside the `geoip_data` folder.

5.  **Configure API Key:**
    * Create a file named `.env` in the project root.
    * Add your Perplexity API key to this file:
        ```dotenv
        PERPLEXITY_API_KEY='YOUR_API_KEY_HERE'
        ```
    * **Important:** The `.gitignore` file ensures `.env` is NOT uploaded to GitHub.

6.  **Set Up Database:**
    ```bash
    python manage.py migrate
    ```

7.  **Create Admin User:**
    ```bash
    python manage.py createsuperuser
    ```
    *(Follow prompts to set username and password for the dashboard login)*

---

## Running the Application

1.  **Activate Virtual Environment** (if not already active):
    ```bash
    .\venv\Scripts\activate
    ```

2.  **Start the Django Server:**
    ```bash
    python manage.py runserver
    ```

3.  **Access the Dashboard:** Open your web browser and go to `http://127.0.0.1:8000/`. Log in using the admin credentials you created.

4.  **Start Simulation:** Navigate to the **Setup** page via the sidebar and click "Setup" for either the **Network** or **Website** service. This will activate the corresponding honeypot simulation and start the AI attack generator.

5.  **Monitor:** Return to the **Dashboard** to view the live attack map, updating charts, stats, and the real-time activity log.

6.  **Stop:** Press `Ctrl+C` in the terminal where `runserver` is running to stop the application.

---

## Technology Stack

* **Backend:** Python, Django
* **Honeypot Services:** Flask, Paramiko, pyftpdlib
* **AI Simulation:** Perplexity AI API, `perplexityai` Python client
* **Geolocation:** `geoip2` Python library, MaxMind GeoLite2 City database
* **Database:** SQLite
* **Frontend:** HTML, Tailwind CSS, JavaScript
* **Visualization:** ApexCharts.js (Charts), Leaflet.js (Map)
* **Development:** Git, GitHub, `python-dotenv`

---

## Screenshots

![alt text](<Screenshot 2025-10-26 113343.png>) ![alt text](<Screenshot 2025-10-26 113355.png>) ![alt text](<Screenshot 2025-10-26 113404.png>) ![alt text](<Screenshot 2025-10-26 113409.png>) ![alt text](<Screenshot 2025-10-26 124454.png>) ![alt text](<Screenshot 2025-10-26 131712.png>) ![alt text](<Screenshot 2025-10-26 133124.png>) ![alt text](<Screenshot 2025-10-26 133130.png>) ![alt text](<Screenshot 2025-10-26 133143.png>) ![alt text](<Screenshot 2025-10-26 133206.png>)