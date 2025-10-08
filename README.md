# Honeypot Dashboard

<div align="center">
  <p>A user-friendly web application that simulates and visualizes network and web-based cyber attacks in real-time.</p>
  <img src="https://forthebadge.com/images/badges/made-with-python.svg">
  <img src="https://forthebadge.com/images/badges/built-with-love.svg">
</div>

## Key Features

-   **Live Dashboard:** Watch simulated attacks appear on the dashboard in real-time without ever needing to refresh the page.
-   **Background Simulation:** Starts generating realistic attack data automatically in the background as soon as a honeypot service is activated.
-   **Data Visualization:** Includes charts and key statistics that update to reflect live attack patterns.
-   **Service Simulation:** Mimics Network (FTP/SSH) and Web services to act as a target for simulated attacks.
-   **Database Logging:** All attack events are reliably stored in a local database for consistency and performance.

---

## Prerequisites

Before you begin, make sure you have the following software installed on your computer:

-   **Python (Version 3.8 or newer):** The programming language this project is built with. You can download it from [python.org](https://www.python.org/downloads/).
-   **Git:** The version control system used to download the project files. You can download it from [git-scm.com](https://git-scm.com/downloads/).

---

## Installation & Setup Guide

Follow these steps in your terminal (like PowerShell or Command Prompt on Windows) to get the project set up and ready to run.

**1. Clone the Repository**
This command downloads the project code from GitHub to your computer.
```bash
git clone [https://github.com/SB2024-25/honeypot-dashboard.git]
2. Navigate into the Project Directory

Bash

cd honeypot-dashboard
3. Create a Virtual Environment
This creates an isolated "bubble" for this project's specific Python libraries so they don't interfere with other projects.

Bash

python -m venv venv
4. Activate the Virtual Environment
You must do this every time you work on the project. You'll know it's active when you see (venv) at the beginning of your terminal prompt.

Bash

.\venv\Scripts\activate
5. Install Dependencies
This command reads the requirements.txt file and installs all the necessary Python libraries into your virtual environment.

Bash

pip install -r requirements.txt
6. Set Up the Database
This command creates the db.sqlite3 file and sets up all the necessary tables.

Bash

python manage.py migrate
7. Create Your Admin Account
This is the username and password you will use to log into the dashboard. Follow the prompts to create your account.

Bash

python manage.py createsuperuser
Setup is now complete!

How to Run and Use the Application
1. Start the Web Server
Make sure your virtual environment is still active ((venv) is visible). Run this command to start the main Django application.

Bash

python manage.py runserver
Your terminal will show you a URL, usually http://127.0.0.1:8000/.

2. Log In
Open the URL from the previous step in your web browser. You will be greeted with a login page. Use the admin account you created during setup to log in.

3. Navigate to the Setup Page
Once logged in, use the navigation sidebar on the left to go to the Setup page.

4. Activate a Honeypot Service
On the Setup page, click the green "Setup" button for either Network or Website. This will start the honeypot service and, in the background, begin generating simulated attack data.

5. View the Live Dashboard!
Navigate back to the Dashboard. You will see statistics, a chart, and a table. Watch the "Recent Activity" table – new attacks will appear at the top automatically every few seconds!

6. Stopping the Application
To stop the entire application, go back to your terminal and press Ctrl + C.



Technology Stack
Backend: Django, Python

Frontend: HTML, TailwindCSS, JavaScript, ApexCharts.js

Honeypot Services: Flask, paramiko, pyftpdlib

Data Simulation: Faker