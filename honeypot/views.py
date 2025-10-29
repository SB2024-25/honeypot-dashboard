# --- IMPORTS ---
import os
import threading
import time
import random
import json
from dotenv import load_dotenv
from django.shortcuts import redirect, render
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from honeypot.Honeypot_Project_final import main
from werkzeug.serving import make_server
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Count
from attack_simulator.models import AttackLog 
from faker import Faker 
from django.conf import settings
import geoip2.database
import geoip2.errors

import google.generativeai as genai
from google.generativeai.types import HarmCategory, HarmBlockThreshold


# --- Load environment variables (can be left in, doesn't hurt) ---
load_dotenv()

# --- Initialize GeoIP Reader (still needed for the map) ---
GEOIP_DATABASE_PATH = os.path.join(settings.BASE_DIR, 'geoip_data', 'GeoLite2-City.mmdb')
geoip_reader = None
try:
    geoip_reader = geoip2.database.Reader(GEOIP_DATABASE_PATH)
    print("GeoIP database loaded successfully.")
except FileNotFoundError:
    print(f"WARNING: GeoIP database not found at {GEOIP_DATABASE_PATH}. Location lookups will be disabled.")
except Exception as e:
    print(f"WARNING: Error loading GeoIP database: {e}. Location lookups will be disabled.")

# ... (after GeoIP reader)

# --- Configure Google AI Client ---
GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY')

if GOOGLE_API_KEY:
    try:
        genai.configure(api_key=GOOGLE_API_KEY)
        print(f"Google AI client configured successfully.")
    except Exception as e:
        print(f"!!! WARNING: Failed to configure Google AI: {e}")
else:
    print("WARNING: GOOGLE_API_KEY not found. AI analysis will be disabled.")


if GOOGLE_API_KEY:
    try:
        genai.configure(api_key=GOOGLE_API_KEY)
        
        model_name = "gemini-1.5-flash"
        ai_model = genai.GenerativeModel(model_name)
        print(f"Google AI client configured with model: {model_name}")
    except Exception as e:
        print(f"!!! WARNING: Failed to configure Google AI: {e}")
else:
    print("WARNING: GOOGLE_API_KEY not found. AI analysis will be disabled.")
# ---------------------------------

# --- Global variables for tracking server state ---
flask_thread = None
flask_server = None
ftp_thread = None
ssh_thread = None
# --- Global variables for the attack generator thread ---
attack_generator_thread = None
generator_stop_event = threading.Event()


# --- Helper functions (remain the same) ---
def is_website_honeypot_active():
    return flask_thread is not None and flask_thread.is_alive()

def is_network_honeypot_active():
    ftp_running = ftp_thread is not None and ftp_thread.is_alive()
    ssh_running = ssh_thread is not None and ssh_thread.is_alive()
    return ftp_running or ssh_running



# --- *** NEW LOCAL Attack Generator Function *** ---
def run_attack_generator(stop_event):
    """
    Runs in a background thread, generates realistic attack data LOCALLY,
    looks up GeoIP, saves to DB, includes scenario logic, and weighted source.
    """
    fake = Faker()
    print("--- Attack generator thread started (LOCAL SIMULATION) ---")
    attack_count = 0
    recent_attacks = []
    MAX_RECENT = 10
    FOLLOW_UP_CHANCE = 0.25 # 25% chance of a follow-up

    # --- Local Data for Simulation (matches models.py) ---
    NETWORK_ATTACKS = {
        'BRUTEFORCE': {'target': ['SSH Login', 'FTP Login'], 'data': 'Failed login: user {}'},
        'PORTSCAN': {'target': ['Port 22', 'Port 80', 'Port 443', 'Port 21'], 'data': 'Nmap scan detected on {}'},
        'RECON': {'target': ['Host Discovery', 'Network Topology'], 'data': 'ARP scan detected from host'},
        'DDOS': {'target': ['Gateway', 'Primary Server'], 'data': 'UDP flood traffic spike detected'},
        'MALWARE_PROP': {'target': ['SMB Share', 'FTP Upload'], 'data': 'Attempted malware upload (e.g., worm)'},
    }
    WEBSITE_ATTACKS = {
        'SQLI': {'target': ['Login Form', 'Search Bar', 'product.php?id=1'], 'data': 'SQL Injection attempt detected'},
        'XSS': {'target': ['Comment Form', 'User Profile', 'Search Query'], 'data': 'Stored XSS payload detected'},
        'DIR_TRAV': {'target': ['/etc/passwd', 'WEB-INF/web.xml', '.../win.ini'], 'data': 'Directory Traversal attempt'},
        'CMD_INJ': {'target': ['/tools/ping.php', 'Network Monitor'], 'data': 'Command Injection attempt (e.g., "ping ...")'},
        'FILE_INC': {'target': ['/include.php?page=', 'index.php?view='], 'data': 'Remote File Inclusion attempt'},
    }
    KEYLOGGER_ATTACKS = {
        'CRED_HARVEST': {'target': ['login_username_field', 'login_password_field'], 'data': 'Keystrokes captured from login form'},
        'DATA_EXFIL': {'target': ['Clipboard', 'Browser Cache'], 'data': 'Sensitive data pattern (e.g., credit card) detected'},
        'KEYLOGGING': {'target': ['Chat Window', 'Email Client'], 'data': 'General keystroke logging active'},
        'SCREEN_CAP': {'target': ['User Desktop', 'Active Window'], 'data': 'Simulated screen capture event'},
    }
    FAKE_USERS = ['admin', 'root', 'support', 'test', 'guest', 'jsmith']
    # -----------------------------------

    while not stop_event.is_set():
        try:
            possible_sources = [] # List for weighted choice
            is_website = is_website_honeypot_active()
            is_network = is_network_honeypot_active()

            if is_website:
                possible_sources.extend(['Website', 'Website', 'Keylogger']) # 2:1 ratio
            if is_network:
                possible_sources.append('Network')

            if not possible_sources:
                stop_event.wait(timeout=1.0)
                continue

            ip_to_use = None
            generated_data = None # This will hold our generated attack dict
            is_follow_up = False

            # --- Scenario Logic ---
            if len(recent_attacks) > 0 and random.random() < FOLLOW_UP_CHANCE:
                last_ip, last_source, last_attack_type = random.choice(recent_attacks)
                ip_to_use = last_ip # Use the same IP
                
                follow_up_attack_type = None
                follow_up_source = None
                follow_up_target = None
                follow_up_data = None
                
                if last_attack_type in ['PORTSCAN', 'RECON'] and last_source == 'Network':
                    follow_up_attack_type = 'BRUTEFORCE'
                    follow_up_source = 'Network'
                    follow_up_target = random.choice(NETWORK_ATTACKS['BRUTEFORCE']['target'])
                    follow_up_data = NETWORK_ATTACKS['BRUTEFORCE']['data'].format(random.choice(FAKE_USERS))

                elif last_attack_type in ['PORTSCAN', 'RECON', 'DIR_TRAV'] and last_source == 'Website':
                     follow_up_attack_type = random.choice(['SQLI', 'XSS', 'CMD_INJ'])
                     follow_up_source = 'Website'
                     follow_up_target = random.choice(WEBSITE_ATTACKS[follow_up_attack_type]['target'])
                     follow_up_data = WEBSITE_ATTACKS[follow_up_attack_type]['data']

                if follow_up_attack_type:
                     print(f"--- Scenario Triggered: Following up {last_attack_type} from {ip_to_use} with {follow_up_attack_type} ---")
                     generated_data = {
                         "source": follow_up_source,
                         "attack_type": follow_up_attack_type,
                         "target_context": follow_up_target,
                         "captured_data": follow_up_data,
                         "location": fake.city() + ", " + fake.country()
                     }
                     is_follow_up = True

            # --- If not a follow-up, generate a new random attack ---
            if not is_follow_up:
                chosen_source = random.choice(possible_sources)
                ip_to_use = fake.ipv4()
                generated_data = {"source": chosen_source, "location": fake.city() + ", " + fake.country()}

                if chosen_source == 'Website':
                    attack_type = random.choice(list(WEBSITE_ATTACKS.keys()))
                    target = random.choice(WEBSITE_ATTACKS[attack_type]['target'])
                    generated_data.update({
                        "attack_type": attack_type,
                        "target_context": target,
                        "captured_data": WEBSITE_ATTACKS[attack_type]['data'].format(target)
                    })
                elif chosen_source == 'Network':
                    attack_type = random.choice(list(NETWORK_ATTACKS.keys()))
                    target = random.choice(NETWORK_ATTACKS[attack_type]['target'])
                    data_str = NETWORK_ATTACKS[attack_type]['data']
                    if '{}' in data_str:
                         data_str = data_str.format(random.choice(FAKE_USERS))
                    generated_data.update({
                        "attack_type": attack_type,
                        "target_context": target,
                        "captured_data": data_str
                    })
                elif chosen_source == 'Keylogger':
                    attack_type = random.choice(list(KEYLOGGER_ATTACKS.keys()))
                    target = random.choice(KEYLOGGER_ATTACKS[attack_type]['target'])
                    generated_data.update({
                        "attack_type": attack_type,
                        "target_context": target,
                        "captured_data": KEYLOGGER_ATTACKS[attack_type]['data'].format(target)
                    })

            # --- Process and Save Attack ---
            if generated_data and ip_to_use:
                location_name = generated_data.get('location', 'Unknown Location')
                latitude = None
                longitude = None

                if geoip_reader:
                    try:
                        response = geoip_reader.city(ip_to_use)
                        if response and response.location:
                            latitude = response.location.latitude
                            longitude = response.location.longitude
                        if response and response.country and response.country.name:
                            location_name = response.country.name # Use GeoIP country for variety
                    except geoip2.errors.AddressNotFoundError:
                        pass # IP not in DB
                    except Exception as e_geoip:
                        print(f"!!! GeoIP lookup error for {ip_to_use}: {e_geoip}")

                # Save the log
                AttackLog.objects.create(
                    ip_address=ip_to_use,
                    location=location_name, # Use GeoIP location if found
                    source=generated_data.get('source'),
                    attack_type=generated_data.get('attack_type'),
                    target_context=generated_data.get('target_context'),
                    captured_data=generated_data.get('captured_data')
                )
                attack_count += 1
                print(f"Attack #{attack_count} saved. IP: {ip_to_use}, Source: {generated_data.get('source')}, Loc: {location_name}")

                # --- Update recent attacks list ---
                new_attack_info = (ip_to_use, generated_data.get('source'), generated_data.get('attack_type'))
                recent_attacks.append(new_attack_info)
                if len(recent_attacks) > MAX_RECENT:
                    recent_attacks.pop(0)

            # --- Sleep logic (faster speed) ---
            if stop_event.is_set(): break
            stop_event.wait(timeout=random.uniform(0.1, 0.5))

        except Exception as e_main:
            print(f"!!! ERROR in attack generator loop: {e_main}")
            print(f"!!! Error details: {type(e_main).__name__}, {e_main.args}")
            print("!!! Pausing generator for 10 seconds...")
            stop_event.wait(timeout=10)

    print(f"--- Attack generator thread stopped after saving {attack_count} attacks ---")


# --- Helper functions to start/stop the generator (remain the same) ---
def start_generator_if_needed():
    """Starts the attack generator thread if it's not already running."""
    global attack_generator_thread
    if attack_generator_thread is None or not attack_generator_thread.is_alive():
        print("--- Starting attack generator thread ---")
        generator_stop_event.clear()
        attack_generator_thread = threading.Thread(target=run_attack_generator, args=(generator_stop_event,), daemon=True)
        attack_generator_thread.start()

def stop_generator_if_idle():
    """Stops the attack generator thread if no honeypot services are active."""
    global attack_generator_thread
    if not is_website_honeypot_active() and not is_network_honeypot_active():
        if attack_generator_thread is not None and attack_generator_thread.is_alive():
            print("--- No services active. Stopping attack generator thread ---")
            generator_stop_event.set()
            attack_generator_thread.join(timeout=5.0)
            if attack_generator_thread.is_alive():
                print("!!! WARNING: Attack generator thread did not stop cleanly after 5s.")
            attack_generator_thread = None
        else:
             attack_generator_thread = None


# === Django Views ===

@login_required
def dashboard(request):
    active_sources = []
    is_website_active = is_website_honeypot_active()
    is_network_active = is_network_honeypot_active()

    if is_website_active:
        active_sources.extend(['Website', 'Keylogger'])
    if is_network_active:
        active_sources.append('Network')

    services_running = is_website_active or is_network_active

    if services_running:
        latest_attacks = AttackLog.objects.filter(source__in=active_sources).order_by('-timestamp')[:50]
        total_attacks = AttackLog.objects.filter(source__in=active_sources).count()
        unique_attackers = AttackLog.objects.filter(source__in=active_sources).values('ip_address').distinct().count()
    else:
        latest_attacks, total_attacks, unique_attackers = [], 0, 0

    context = {
        "active": "dashboard",
        "services_active": services_running,
        "total_attacks": total_attacks,
        "unique_attackers": unique_attackers,
        "latest_attacks": latest_attacks,
    }
    return render(request, 'dashboard.html', context)

# --- API View for Stats ---
def get_stats_data_api(request):
    total_attacks = 0
    unique_attackers = 0
    active_sources = [] 

    if is_website_honeypot_active():
        active_sources.extend(['Website', 'Keylogger'])
    if is_network_honeypot_active():
        active_sources.append('Network')

    if active_sources:
        total_attacks = AttackLog.objects.filter(source__in=active_sources).count()
        unique_attackers = AttackLog.objects.filter(source__in=active_sources).values('ip_address').distinct().count()

    stats_data = {
        'total_attacks': total_attacks,
        'unique_attackers': unique_attackers,
    }
    return JsonResponse(stats_data)

# --- API View for Pie Chart ---
def attack_source_data(request):
    active_sources = []
    if is_website_honeypot_active():
        active_sources.extend(['Website', 'Keylogger'])
    if is_network_honeypot_active():
        active_sources.append('Network')

    data = []
    if active_sources:
        data = AttackLog.objects.filter(source__in=active_sources) \
                                .values('source') \
                                .annotate(count=Count('source')) \
                                .order_by('-count')

    source_map = dict(AttackLog.SOURCE_CHOICES)
    labels = [source_map.get(item['source'], item['source']) for item in data]
    counts = [item['count'] for item in data]

    chart_data = {
        'labels': labels,
        'data': counts,
    }
    return JsonResponse(chart_data)

@login_required
def analyze(request):
    return render(request, "analyze.html")


# --- API View for Bar Chart ---
def attack_type_data(request):
    active_sources = []
    if is_website_honeypot_active():
        active_sources.extend(['Website', 'Keylogger'])
    if is_network_honeypot_active():
        active_sources.append('Network')

    data = []
    if active_sources:
        data = AttackLog.objects.filter(source__in=active_sources).values('attack_type').annotate(count=Count('attack_type')).order_by('-count')

    attack_model = AttackLog()
    attack_type_mapping = dict(attack_model.ATTACK_TYPE_CHOICES)
    labels = [attack_type_mapping.get(item['attack_type'], item['attack_type']) for item in data]
    counts = [item['count'] for item in data]

    chart_data = { 'labels': labels, 'data': counts, }
    return JsonResponse(chart_data)

# --- API View for Live Table ---
def get_new_attacks_api(request):
    latest_id = request.GET.get('latest_id', 0)
    try:
        latest_id = int(latest_id)
    except (ValueError, TypeError):
        latest_id = 0

    active_sources = []
    if is_website_honeypot_active():
        active_sources.extend(['Website', 'Keylogger'])
    if is_network_honeypot_active():
        active_sources.append('Network')

    data = []
    if active_sources:
        new_attacks = AttackLog.objects.filter(
            id__gt=latest_id,
            source__in=active_sources
        ).order_by('-timestamp')[:20]

        data = list(new_attacks.values(
            'id', 'timestamp', 'source', 'ip_address', 'location',
            'attack_type', 'target_context', 'captured_data'
        ))

        source_map = dict(AttackLog.SOURCE_CHOICES)
        type_map = dict(AttackLog.ATTACK_TYPE_CHOICES)
        for attack in data:
            attack['source_display'] = source_map.get(attack['source'], attack['source'])
            attack['attack_type_display'] = type_map.get(attack['attack_type'], attack['attack_type'])
            attack['latitude'] = None
            attack['longitude'] = None

            if geoip_reader and attack['ip_address']:
                try:
                    response = geoip_reader.city(attack['ip_address'])
                    if response and response.location:
                        attack['latitude'] = response.location.latitude
                        attack['longitude'] = response.location.longitude
                except geoip2.errors.AddressNotFoundError:
                    pass
                except Exception as e_geoip_api:
                    print(f"GeoIP API lookup error for {attack['ip_address']}: {e_geoip_api}")

    return JsonResponse({'attacks': data})


@csrf_exempt
def start_flask_server(request):
    global flask_thread, flask_server
    if request.method == 'POST':
        if not is_website_honeypot_active():
            print("--- Clearing existing attack logs ---")
            AttackLog.objects.all().delete()
            # with cache_lock:
            #     attack_cache.clear() # No cache to clear
            print("--- Starting Flask server thread ---")
            def run_flask():
                global flask_server
                try:
                    if hasattr(main, 'WebsiteTrap') and hasattr(main.WebsiteTrap, 'app'):
                         flask_server = make_server('0.0.0.0', 5000, main.WebsiteTrap.app, threaded=True)
                         print(f"Flask server starting on 0.0.0.0:5000")
                         flask_server.serve_forever()
                    else:
                         print("!!! ERROR: Flask app object not found in main.WebsiteTrap.app")
                except OSError as e_os:
                     print(f"!!! ERROR starting Flask server (OSError): {e_os}")
                     print("!!! Port 5000 might already be in use.")
                except Exception as e_flask_run:
                     print(f"!!! UNEXPECTED ERROR starting Flask server: {e_flask_run}")

            flask_thread = threading.Thread(target=run_flask, daemon=True)
            flask_thread.start()
            time.sleep(0.5)
            if is_website_honeypot_active():
                start_generator_if_needed()
                return JsonResponse({'status': 'started', 'ip': '0.0.0.0', 'port': '5000'})
            else:
                 print("!!! Flask server thread failed to start or stay running.")
                 flask_thread = None
                 return JsonResponse({'status': 'error', 'message':'Flask server failed to start.'}, status=500)
        else:
            return JsonResponse({'status': 'already_running'})
    return JsonResponse({'error': 'Invalid request method'}, status=400)

@csrf_exempt
def stop_flask_server(request):
    global flask_thread, flask_server
    if request.method == 'POST':
        if is_website_honeypot_active():
            print("--- Stopping Flask server ---")
            try:
                if flask_server:
                    print("--- (Flask server shutdown relies on daemon thread exit or server reload) ---")
            except Exception as e_flask_stop:
                print(f"!!! Error during Flask server shutdown attempt: {e_flask_stop}")

            stop_generator_if_idle()

            if flask_thread:
                print("--- Flask thread reference cleared ---")

            flask_thread = None
            flask_server = None
            return JsonResponse({'status': 'stopped'})
        else:
            if flask_thread is not None and not flask_thread.is_alive():
                flask_thread = None
                flask_server = None
            return JsonResponse({'status': 'not_running'})
    return JsonResponse({'error': 'Invalid request method'}, status=400)


@csrf_exempt
def start_network_server(request):
    global ftp_thread, ssh_thread
    if request.method == 'POST':
        if not is_network_honeypot_active():
            print("--- Clearing existing attack logs ---")
            AttackLog.objects.all().delete()
            # with cache_lock:
            #     attack_cache.clear() # No cache to clear
            print("--- Starting Network server threads (FTP & SSH) ---")
            
            # --- FIX: Create the FTP 'home' directory ---
            try:
                ftp_home_dir = os.path.join(settings.BASE_DIR, 'honeypot', 'Honeypot_Project_final', 'home')
                if not os.path.exists(ftp_home_dir):
                    print(f"FTP 'home' directory not found. Creating it at: {ftp_home_dir}")
                    os.makedirs(ftp_home_dir)
            except Exception as e_dir:
                print(f"!!! ERROR: Could not create FTP 'home' directory: {e_dir}")
            # ---------------------------------------------

            ftp_started = False
            ssh_started = False
            try:
                if hasattr(main, 'FtpHoneypot') and hasattr(main.FtpHoneypot, 'run_ftp_server'):
                     ftp_thread = threading.Thread(target=main.FtpHoneypot.run_ftp_server, daemon=True)
                     ftp_thread.start()
                     ftp_started = True
                else:
                     print("!!! ERROR: main.FtpHoneypot.run_ftp_server not found.")

                if hasattr(main, 'SSHhoneypot') and hasattr(main.SSHhoneypot, 'start_ssh_server'):
                     ssh_thread = threading.Thread(target=main.SSHhoneypot.start_ssh_server, daemon=True)
                     ssh_thread.start()
                     ssh_started = True
                else:
                     print("!!! ERROR: main.SSHhoneypot.start_ssh_server not found.")

                if ftp_started or ssh_started:
                     time.sleep(0.5)
                     if is_network_honeypot_active():
                        start_generator_if_needed()
                        return JsonResponse({'status': 'started'})
                     else:
                         print("!!! Network threads failed to start or stay running.")
                         if ftp_thread and not ftp_thread.is_alive(): ftp_thread = None
                         if ssh_thread and not ssh_thread.is_alive(): ssh_thread = None
                         return JsonResponse({'status': 'error', 'message':'Network server threads failed.'}, status=500)
                else:
                      return JsonResponse({'status': 'error', 'message':'Network server functions not found.'}, status=500)

            except Exception as e_net_start:
                 print(f"!!! ERROR starting network threads: {e_net_start}")
                 ftp_thread = None
                 ssh_thread = None
                 return JsonResponse({'status': 'error', 'message': str(e_net_start)}, status=500)
        else:
            return JsonResponse({'status': 'already_running'})
    return JsonResponse({'error': 'Invalid request method'}, status=400)

@csrf_exempt
def stop_network_server(request):
    global ftp_thread, ssh_thread
    stopped_cleanly = True
    if request.method == 'POST':
        network_was_active = is_network_honeypot_active()

        if network_was_active:
            print("--- Attempting to stop network services (FTP & SSH) ---")
            try:
                if hasattr(main, 'FtpHoneypot') and hasattr(main.FtpHoneypot, 'stop_ftp_server'):
                    main.FtpHoneypot.stop_ftp_server()
                else:
                     print("!!! WARNING: Cannot signal FTP server to stop (function missing).")

                if hasattr(main, 'SSHhoneypot') and hasattr(main.SSHhoneypot, 'stop_ssh_server'):
                    main.SSHhoneypot.stop_ssh_server()
                else:
                     print("!!! WARNING: Cannot signal SSH server to stop (function missing).")

            except Exception as e_stop_signal:
                 print(f"!!! Error signaling network services to stop: {e_stop_signal}")

            stop_generator_if_idle()

            if ftp_thread and ftp_thread.is_alive():
                ftp_thread.join(timeout=2.0)
                if ftp_thread.is_alive():
                    print("!!! WARNING: FTP thread did not stop cleanly.")
                    stopped_cleanly = False
            if ssh_thread and ssh_thread.is_alive():
                ssh_thread.join(timeout=2.0)
                if ssh_thread.is_alive():
                     print("!!! WARNING: SSH thread did not stop cleanly.")
                     stopped_cleanly = False

        ftp_thread = None
        ssh_thread = None
        print("--- Network service threads cleared ---")
        stop_generator_if_idle()
        return JsonResponse({'status': 'stopped', 'stopped_cleanly': stopped_cleanly})

    if ftp_thread is not None and not ftp_thread.is_alive(): ftp_thread = None
    if ssh_thread is not None and not ssh_thread.is_alive(): ssh_thread = None
    return JsonResponse({'status': 'not_running'})


def network_setup(request):
    return JsonResponse({'status': 'running' if is_network_honeypot_active() else 'stopped'})

def server_setup(request):
    return JsonResponse({'status': 'running' if is_website_honeypot_active() else 'stopped'})

@login_required
def setup(request):
    return render(request,"setup.html",{"active":"setup"})

@login_required
def Keylogger(request):
    service_active = is_website_honeypot_active()
    attack_logs = []
    if service_active:
         attack_logs = AttackLog.objects.filter(source='Keylogger').order_by('-timestamp')[:200]
    context = {'active': 'Keylogger', 'attack_logs': attack_logs, 'source_name': 'Keylogger', 'service_is_active': service_active }
    return render(request, "network.html", context)

@login_required
def network(request):
    service_active = is_network_honeypot_active()
    attack_logs = []
    if service_active:
         attack_logs = AttackLog.objects.filter(source='Network').order_by('-timestamp')[:200]
    context = { 'active': 'network', 'attack_logs': attack_logs, 'source_name': 'Network Honeypot', 'service_is_active': service_active }
    return render(request, "network.html", context)

@login_required
def website(request):
    service_active = is_website_honeypot_active()
    attack_logs = []
    if service_active:
         attack_logs = AttackLog.objects.filter(source='Website').order_by('-timestamp')[:200]
    context = { 'active': 'website', 'attack_logs': attack_logs, 'source_name': 'Website Honeypot', 'service_is_active': service_active }
    return render(request, "network.html", context)

@login_required
@csrf_exempt # Use csrf_exempt for simplicity in API calls from JS
def analyze_attack_api(request):
    if request.method == 'POST':
        if not ai_model:
            return JsonResponse({'error': 'AI client is not configured.'}, status=500)

        try:
            data = json.loads(request.body)
            attack_id = data.get('attack_id')

            # Fetch the attack from the database
            attack = AttackLog.objects.get(id=attack_id)

            # Create a simple description of the attack
            attack_desc = f"""
            - Source: {attack.get_source_display()}
            - Attack Type: {attack.get_attack_type_display()}
            - Target: {attack.target_context}
            - Captured Data: {attack.captured_data}
            - Location: {attack.location}
            """

            prompt = f"""
            You are a senior cybersecurity analyst. An alert just occurred with these details:
            {attack_desc}

            Provide a brief analysis for a security dashboard.
            Format your response in simple HTML using <ul> and <li> bullet points (3-4 points max).
            Briefly explain:
            1. What this attack is.
            2. What the attacker was likely trying to achieve.
            3. A common mitigation step.

            Keep the descriptions concise. Do not include markdown or the word "Analysis:".
            Example: "<ul><li>...</li><li>...</li></ul>"
            """

            # Configure safety settings to be less restrictive
            safety_settings = {
                HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
                HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
                HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
                HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
            }

            response = ai_model.generate_content(
                prompt,
                safety_settings=safety_settings
            )

            # Return the AI's text response
            return JsonResponse({'analysis': response.text})

        except AttackLog.DoesNotExist:
            return JsonResponse({'error': 'Attack not found.'}, status=404)
        except Exception as e:
            print(f"!!! AI Analysis Error: {e}")
            # Check for rate limit error
            if "429" in str(e):
                 return JsonResponse({'error': 'AI analysis quota exceeded. Please try again later.'}, status=429)
            return JsonResponse({'error': f'An error occurred during analysis: {e}'}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)


def handlelogin(request):
    if request.method=="POST":
        Username=request.POST.get("loginusername")
        Password=request.POST.get("loginpassword")
        if Username and Password:
            user=authenticate(request, username=Username, password=Password)
            if user is not None:
                login(request,user)
                return redirect("dashboard")
            else:
                messages.error(request,"Username or Password is incorrect.")
        else:
            messages.error(request,"Please enter both username and password.")
        return redirect('handlelogin')
    return render(request,'login.html')

@login_required
def analyze(request):
    from django.utils.html import strip_tags
    if not ai_model:
        return render(request, "analyze.html", {"error": "AI model not configured."})

    summary = None
    analysis_text = ""
    try:
        # Gather attack data for context
        all_attacks = AttackLog.objects.all().order_by("-timestamp")[:500]
        if all_attacks.exists():
            combined_info = "\n".join([
                f"{a.attack_type} on {a.source} from {a.location}" for a in all_attacks
            ])
            prompt = f"""
            You are a cybersecurity analyst reviewing honeypot logs. 
            Summarize the main attack patterns, techniques used, and give 
            3–4 concise defensive recommendations to mitigate them. 

            Logs summary:
            {strip_tags(combined_info)}
            """
            response = ai_model.generate_content(prompt)
            analysis_text = response.text or "No response received."
        else:
            analysis_text = "No attack data available to analyze."
    except Exception as e:
        analysis_text = f"Error during AI analysis: {e}"

    return render(request, "analyze.html", {"analysis_text": analysis_text})

@csrf_exempt
@login_required
def analyze_api(request):
    if request.method != "GET":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        # Get recent attacks for analysis
        recent_attacks = AttackLog.objects.all().order_by("-timestamp")[:80]
        
        if not recent_attacks.exists():
            return JsonResponse({"summary": "No attack data available for analysis."})

        # Create attack summary statistics
        attack_counts = {}
        source_counts = {}
        locations = {}
        
        for attack in recent_attacks:
            attack_type = attack.get_attack_type_display()
            source = attack.get_source_display()
            location = attack.location
            
            attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1
            source_counts[source] = source_counts.get(source, 0) + 1
            locations[location] = locations.get(location, 0) + 1

        # Get top items
        top_attacks = sorted(attack_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        top_sources = sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:3]
        top_locations = sorted(locations.items(), key=lambda x: x[1], reverse=True)[:3]

        # Create improved analysis prompt with bullet point focus
        prompt = f"""
As a senior cybersecurity analyst, analyze these honeypot attacks and provide a structured security briefing:

ATTACK OVERVIEW:
- Total Attacks: {len(recent_attacks)}
- Time Period: Recent activity
- Top Attack Types: {', '.join([f'{k} ({v} occurrences)' for k, v in top_attacks])}
- Primary Sources: {', '.join([f'{k} ({v} attacks)' for k, v in top_sources])}
- Common Locations: {', '.join([k for k, v in top_locations])}

RECENT ATTACK SAMPLES:
{chr(10).join([f"• {a.get_attack_type_display()} from {a.ip_address} at {a.timestamp.strftime('%H:%M')}" for a in recent_attacks[:8]])}

Please provide a CLEAN, STRUCTURED analysis using ONLY HTML bullet points (<ul> and <li> tags). Organize it in these sections:

<h3>🔍 Threat Assessment</h3>
<ul>
<li>[Main security risks identified]</li>
<li>[Attacker behavior patterns]</li>
<li>[Criticality level assessment]</li>
</ul>

<h3>🛡️ Immediate Actions Required</h3>
<ul>
<li>[3-4 specific security measures]</li>
<li>[Configuration changes needed]</li>
<li>[Monitoring priorities]</li>
</ul>

<h3>📈 Attack Patterns</h3>
<ul>
<li>[Most frequent attack methods]</li>
<li>[Source distribution insights]</li>
<li>[Emerging trends to watch]</li>
</ul>

Keep it concise, professional, and focused on actionable insights. Use only the HTML structure above.
"""

        # Try Ollama analysis
        try:
            import ollama
            
            response = ollama.generate(
                model='llama3.2:3b',  # Use whatever model you downloaded
                prompt=prompt,
                options={
                    'temperature': 0.3,
                    'top_k': 40,
                    'top_p': 0.9,
                }
            )
            
            summary = response['response']
            
            # Ensure we have proper bullet point formatting
            if not summary or len(summary.strip()) < 50:
                summary = generate_fallback_analysis(attack_counts, source_counts, len(recent_attacks))
            elif '<ul>' not in summary and '<li>' not in summary:
                # If AI didn't use bullet points, wrap the response
                summary = f"<ul><li>{summary.replace(chr(10), '</li><li>')}</li></ul>"
                
        except ImportError:
            # Ollama not installed
            summary = """
            <div class="bg-blue-50 dark:bg-blue-900/20 p-4 rounded-lg border border-blue-200">
                <p class="text-blue-700 dark:text-blue-400 mb-3">To enable free AI-powered security analysis:</p>
                <div class="bg-gray-800 text-green-400 p-3 rounded font-mono text-sm">
                    <div>curl -fsSL https://ollama.ai/install.sh | sh</div>
                    <div>ollama pull llama3.2:3b</div>
                </div>
                <p class="text-blue-700 dark:text-blue-400 mt-3 text-sm">Then refresh this page for instant AI analysis!</p>
            </div>
            """
            
        except Exception as ollama_error:
            print(f"Ollama error: {ollama_error}")
            # Fallback to basic analysis
            summary = generate_fallback_analysis(attack_counts, source_counts, len(recent_attacks))

        return JsonResponse({"summary": summary})

    except Exception as exc:
        print(f"Analyze API error: {str(exc)}")
        return JsonResponse({"error": "Analysis service temporarily unavailable. Please try again."}, status=500)


def generate_fallback_analysis(attack_counts, source_counts, total_attacks):
    """Generate a basic analysis when Ollama is unavailable"""
    top_threats = list(attack_counts.keys())[:3]
    top_sources = list(source_counts.keys())[:2]
    
    return f"""
    <div class="bg-yellow-50 dark:bg-yellow-900/20 p-4 rounded-lg border border-yellow-200">
        <h3 class="font-bold text-lg text-yellow-800 dark:text-yellow-300 mb-3">Security Analysis</h3>
        
        <h4 class="font-semibold text-yellow-700 dark:text-yellow-400">🔍 Threat Assessment</h4>
        <ul class="list-disc list-inside text-yellow-700 dark:text-yellow-400 text-sm mt-1 mb-3">
            <li>Total attacks detected: <strong>{total_attacks}</strong></li>
            <li>Primary threats: {', '.join(top_threats)}</li>
            <li>Attack sources: {', '.join(top_sources)}</li>
        </ul>
        
        <h4 class="font-semibold text-yellow-700 dark:text-yellow-400">🛡️ Immediate Actions</h4>
        <ul class="list-disc list-inside text-yellow-700 dark:text-yellow-400 text-sm mt-1 mb-3">
            <li>Monitor for repeated {top_threats[0] if top_threats else 'attack'} patterns</li>
            <li>Review and strengthen firewall rules</li>
            <li>Implement rate limiting on vulnerable services</li>
            <li>Keep all honeypot services updated</li>
        </ul>
        
        <h4 class="font-semibold text-yellow-700 dark:text-yellow-400">📈 Monitoring Focus</h4>
        <ul class="list-disc list-inside text-yellow-700 dark:text-yellow-400 text-sm mt-1">
            <li>Watch for coordinated attack campaigns</li>
            <li>Track IP addresses with multiple attack types</li>
            <li>Monitor for new vulnerability exploitation attempts</li>
        </ul>
        
        <p class="text-yellow-600 dark:text-yellow-500 text-xs mt-3">
        </p>
    </div>
    """

def generate_fallback_analysis(attack_counts, source_counts, total_attacks):
    """Generate a basic analysis when Ollama is unavailable"""
    top_threats = list(attack_counts.keys())[:3]
    top_sources = list(source_counts.keys())[:2]
    
    return f"""
    <div class="bg-yellow-50 dark:bg-yellow-900/20 p-4 rounded-lg border border-yellow-200">
        <h3 class="font-bold text-lg text-yellow-800 dark:text-yellow-300 mb-3">Security Analysis</h3>
        
        <div class="mb-3">
            <h4 class="font-semibold text-yellow-700 dark:text-yellow-400">📊 Attack Overview</h4>
            <ul class="list-disc list-inside text-yellow-700 dark:text-yellow-400 text-sm mt-1">
                <li>Total attacks detected: <strong>{total_attacks}</strong></li>
                <li>Primary threats: {', '.join(top_threats)}</li>
                <li>Main sources: {', '.join(top_sources)}</li>
            </ul>
        </div>
        
        <div class="mb-3">
            <h4 class="font-semibold text-yellow-700 dark:text-yellow-400">🛡️ Recommendations</h4>
            <ul class="list-disc list-inside text-yellow-700 dark:text-yellow-400 text-sm mt-1">
                <li>Monitor for repeated {top_threats[0] if top_threats else 'attack'} patterns</li>
                <li>Review firewall rules for suspicious traffic</li>
                <li>Keep honeypot services updated and monitored</li>
            </ul>
        </div>
        
        <p class="text-yellow-600 dark:text-yellow-500 text-xs mt-2">
        </p>
    </div>
    """
@login_required
def handlelogout(request):
    
    
    logout(request)
    messages.info(request,"Logged out Successfully!")
    return redirect('handlelogin')