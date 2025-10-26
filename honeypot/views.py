# --- IMPORTS ---
import os
import threading
import time
import random
import json
from dotenv import load_dotenv # Loads environment variables from .env file
# Removed google.generativeai and mistralai imports
from django.shortcuts import redirect, render
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from honeypot.Honeypot_Project_final import main # Use absolute import
from werkzeug.serving import make_server
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Count
from attack_simulator.models import AttackLog
from faker import Faker # Generates fake data
from django.conf import settings # Import Django settings
import geoip2.database # GeoIP library
import geoip2.errors # Import specific GeoIP errors

# --- Import Perplexity ---
from perplexity import Client # Correct import for perplexityai library
# -------------------------

# --- Load environment variables ---
load_dotenv()
PERPLEXITY_API_KEY = os.getenv('PERPLEXITY_API_KEY') # Load Perplexity key

# --- Initialize GeoIP Reader ---
GEOIP_DATABASE_PATH = os.path.join(settings.BASE_DIR, 'geoip_data', 'GeoLite2-City.mmdb')
geoip_reader = None
try:
    geoip_reader = geoip2.database.Reader(GEOIP_DATABASE_PATH)
    print("GeoIP database loaded successfully.")
except FileNotFoundError:
    print(f"WARNING: GeoIP database not found at {GEOIP_DATABASE_PATH}. Location lookups will be disabled.")
except Exception as e:
    print(f"WARNING: Error loading GeoIP database: {e}. Location lookups will be disabled.")


# --- Global variables for tracking server state ---
flask_thread = None
flask_server = None
ftp_thread = None
ssh_thread = None
# --- Global variables for the attack generator thread ---
attack_generator_thread = None
generator_stop_event = threading.Event()

# --- Helper functions to check service status ---
def is_website_honeypot_active():
    """Checks if the Flask (Website) honeypot thread is running."""
    return flask_thread is not None and flask_thread.is_alive()

def is_network_honeypot_active():
    """Checks if the FTP or SSH (Network) honeypot threads are running."""
    ftp_running = ftp_thread is not None and ftp_thread.is_alive()
    ssh_running = ssh_thread is not None and ssh_thread.is_alive()
    return ftp_running or ssh_running

# --- Perplexity AI Attack Generation Function ---
# --- *** UPDATED generate_ai_attack function for Perplexity *** ---
# ADD source_to_generate parameter
def generate_ai_attack(source_to_generate): # Takes the specific source as input
    """
    Uses the Perplexity AI official client to generate attacks for a SPECIFIC source.
    Returns a dictionary with attack data or None if failed.
    """
    if not PERPLEXITY_API_KEY:
        print("!!! Perplexity AI generation skipped: PERPLEXITY_API_KEY not found.")
        return None

    try:
        client = Client(api_key=PERPLEXITY_API_KEY)
        model_name = "sonar-pro" # Using the model confirmed to work

        # Construct the prompt, forcing the source
        messages = [
            {
                "role": "system",
                "content": "You are a cybersecurity attack simulator. Output ONLY a single raw JSON object representing one honeypot log entry. Ensure the JSON is valid.",
            },
            {
                "role": "user",
                "content": f"""
                    Generate JSON for one log entry.
                    The source MUST be "{source_to_generate}". # <<<--- FORCE THE SOURCE
                    Use keys "source", "attack_type", "target_context", "captured_data", and "location".

                    - location: MUST be a plausible real-world city and country. Be diverse.
                    - attack_type: Choose ONE appropriate type for the "{source_to_generate}" source:
                        - If source is Network: Choose from "BRUTEFORCE", "PORTSCAN", "SNIFFING", "MITM", "RECON", "MALWARE_PROP", "DDOS", "OTHER".
                        - If source is Website: Choose from "SQLI", "XSS", "CSRF", "DIR_TRAV", "CMD_INJ", "FILE_INC", "XXE", "DDOS", "BRUTEFORCE", "OTHER".
                        - If source is Keylogger: Choose from "KEYLOGGING", "CRED_HARVEST", "DATA_EXFIL", "SCREEN_CAP", "BRUTEFORCE", "OTHER".
                    - target_context: Be specific and relevant to the attack_type.
                    - captured_data: MUST be a *brief, safe description* relevant to the attack_type.
                        - *Do not include actual code, payloads, passwords, or sensitive data.*

                    Be concise. JSON output only. Example (ensure source matches requested "{source_to_generate}"): {{"source": "{source_to_generate}", "attack_type": "...", "target_context": "...", "captured_data": "...", "location": "..."}}
                """,
            },
        ]

        response = client.chat.completions.create(
            model=model_name,
            messages=messages,
        )

        # Extract the JSON content
        if response.choices and response.choices[0].message and response.choices[0].message.content:
            json_text = response.choices[0].message.content.strip()
            # Try to remove potential markdown formatting
            json_text = json_text.replace('```json', '').replace('```', '').strip()
            # print(f"DEBUG: AI Raw JSON Text: {json_text}") # Uncomment for deep debug

            attack_data = json.loads(json_text)

            # Basic validation
            required_keys = ["source", "attack_type", "target_context", "captured_data", "location"]
            if not all(k in attack_data for k in required_keys):
                print(f"!!! Perplexity response missing keys: {attack_data}")
                return None

            # --- VALIDATE the AI used the CORRECT source ---
            returned_source = attack_data.get("source")
            if returned_source != source_to_generate:
                print(f"!!! Perplexity returned WRONG source: Expected '{source_to_generate}', Got '{returned_source}'")
                # Optionally, you could try calling the AI again here, or just return None
                return None # Fail if AI didn't follow instruction

            return attack_data
        else:
            print(f"!!! Perplexity response structure unexpected or empty: {response}")
            return None

    except json.JSONDecodeError as e_json:
        raw_content = "N/A"
        try: # Try to get raw content for logging
             if response and response.choices:
                 raw_content = response.choices[0].message.content
        except Exception:
             pass
        print(f"!!! Perplexity response JSON decode error: {e_json}. Raw content: {raw_content}")
        return None
    except Exception as e_pplx: # Catch potential errors from the perplexityai library
        print(f"!!! Perplexity AI generation failed: {type(e_pplx).__name__} - {e_pplx}")
        if "invalid model" in str(e_pplx).lower():
            print("!!! HINT: The model 'sonar-pro' might still be incorrect. Please verify the exact model name in Perplexity's API documentation.")
        return None

# --- *** UPDATED run_attack_generator function *** ---
def run_attack_generator(stop_event):
    """
    Runs in a background thread, generates attacks via AI (forcing source based on weight),
    looks up GeoIP, saves to DB, includes basic scenario logic, faster speed.
    """
    fake = Faker()
    print("--- Attack generator thread started ---")
    attack_count = 0
    recent_attacks = []
    MAX_RECENT = 10
    FOLLOW_UP_CHANCE = 0.0

    while not stop_event.is_set():
        try:
            possible_sources = [] # List for weighted choice
            is_website = is_website_honeypot_active()
            is_network = is_network_honeypot_active()

            # Build the list for weighted random choice
            if is_website:
                # Add Website 5 times, Keylogger once for a 5:1 ratio
                possible_sources.extend(['Website', 'Website' ,'Keylogger'])
            if is_network:
                possible_sources.append('Network') # Network added if active

            if not possible_sources: # Skip if no services are active
                stop_event.wait(timeout=1.0)
                continue

            # --- Determine Attack Type: Follow-up or New ---
            ip_to_use = None
            ai_generated_data = None # Reset ai_generated_data
            is_follow_up = False     # Flag to track if it's a scenario follow-up

            # Scenario Logic (Check for follow-up)
            if len(recent_attacks) > 0 and random.random() < FOLLOW_UP_CHANCE:
                last_ip, last_source, last_attack_type = random.choice(recent_attacks)
                ip_to_use = last_ip # Use the same IP for follow-up
                follow_up_attack_type = None
                follow_up_source = None
                follow_up_target = None

                # Define follow-up rules
                if last_attack_type in ['PORTSCAN', 'RECON'] and last_source == 'Network':
                    follow_up_attack_type = 'BRUTEFORCE'
                    follow_up_source = 'Network'
                    follow_up_target = random.choice(['SSH Login', 'FTP Login'])
                elif last_attack_type in ['PORTSCAN', 'RECON', 'DIR_TRAV'] and last_source == 'Website':
                     follow_up_attack_type = random.choice(['SQLI', 'XSS', 'CMD_INJ']) # Common exploits after scanning
                     follow_up_source = 'Website'
                     follow_up_target = random.choice(['Search Form', 'Login API', '/product?id='])
                # (Add more rules if needed)

                if follow_up_attack_type:
                     print(f"--- Scenario Triggered: Following up {last_attack_type} from {ip_to_use} with {follow_up_attack_type} ---")
                     # Construct follow-up data directly (no AI call needed here)
                     ai_generated_data = {
                         "source": follow_up_source,
                         "attack_type": follow_up_attack_type,
                         "target_context": follow_up_target,
                         "captured_data": f"Follow-up attempt after {last_attack_type}",
                         "location": fake.city() + ", " + fake.country() # Fake location for follow-up
                     }
                     is_follow_up = True # Mark this as a follow-up

            # If not a follow-up, choose a source based on weight and call AI
            if not is_follow_up:
                # --- Choose the source WE want based on weight ---
                chosen_source_to_generate = random.choice(possible_sources)
                # -----------------------------------------------

                # --- Call AI, passing the SPECIFIC source chosen ---
                # print(f"DEBUG: Asking AI to generate source='{chosen_source_to_generate}'") # Optional debug
                ai_generated_data = generate_ai_attack(chosen_source_to_generate)
                # --------------------------------------------------

                if ai_generated_data:
                    ip_to_use = fake.ipv4() # Generate a new IP for random attacks
                else:
                    # AI failed for the chosen source, print message and skip iteration
                    print(f"AI generation failed for requested source '{chosen_source_to_generate}'. Skipping...")
                    # Optional: Add a small delay here if AI fails frequently
                    # time.sleep(1)
                    continue # Skip to next loop iteration

            # --- Process and Save Attack (Runs for both AI-generated and follow-up) ---
            if ai_generated_data and ip_to_use:
                location_name = ai_generated_data.get('location', 'Unknown Location')
                latitude = None
                longitude = None

                # GeoIP lookup for map coordinates based on ip_to_use
                if geoip_reader:
                    try:
                        response = geoip_reader.city(ip_to_use)
                        if response and response.location:
                            latitude = response.location.latitude
                            longitude = response.location.longitude
                    except geoip2.errors.AddressNotFoundError:
                        pass
                    except Exception as e_geoip:
                        print(f"!!! GeoIP lookup error for {ip_to_use}: {e_geoip}")

                # Save the log
                AttackLog.objects.create(
                    ip_address=ip_to_use,
                    location=location_name,
                    source=ai_generated_data.get('source'),
                    attack_type=ai_generated_data.get('attack_type'),
                    target_context=ai_generated_data.get('target_context'),
                    captured_data=ai_generated_data.get('captured_data')
                )
                attack_count += 1
                print(f"Attack #{attack_count} saved. IP: {ip_to_use}, Source: {ai_generated_data.get('source')}, Loc: {location_name}")

                # --- Update recent attacks list ---
                new_attack_info = (ip_to_use, ai_generated_data.get('source'), ai_generated_data.get('attack_type'))
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
    

# Add near your other API views

def get_stats_data_api(request):
    """
    API endpoint to return current attack statistics (total, unique IPs).
    """
    total_attacks = 0
    unique_attackers = 0
    active_sources = [] # Determine active sources again

    if is_website_honeypot_active():
        active_sources.extend(['Website', 'Keylogger'])
    if is_network_honeypot_active():
        active_sources.append('Network')

    if active_sources:
        # Query database for current counts based on active sources
        total_attacks = AttackLog.objects.filter(source__in=active_sources).count()
        unique_attackers = AttackLog.objects.filter(source__in=active_sources).values('ip_address').distinct().count()

    stats_data = {
        'total_attacks': total_attacks,
        'unique_attackers': unique_attackers,
    }
    return JsonResponse(stats_data)

def attack_source_data(request):
    """
    Provides data for the source distribution pie chart.
    Counts occurrences of each attack source.
    """
    active_sources = []
    if is_website_honeypot_active():
        active_sources.extend(['Website', 'Keylogger'])
    if is_network_honeypot_active():
        active_sources.append('Network')

    data = []
    if active_sources:
        # Query the database, group by 'source', count each group
        data = AttackLog.objects.filter(source__in=active_sources) \
                                .values('source') \
                                .annotate(count=Count('source')) \
                                .order_by('-count') # Order ensures slices are somewhat consistent

    # Get the full display names (e.g., 'Website Honeypot')
    source_map = dict(AttackLog.SOURCE_CHOICES)
    labels = [source_map.get(item['source'], item['source']) for item in data]
    counts = [item['count'] for item in data]

    chart_data = {
        'labels': labels,
        'data': counts,
    }
    return JsonResponse(chart_data)

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
                    print("--- (Flask server shutdown relies on daemon thread exit) ---")
            except Exception as e_flask_stop:
                print(f"!!! Error during Flask server shutdown attempt: {e_flask_stop}")

            stop_generator_if_idle()

            if flask_thread:
                flask_thread.join(timeout=2.0)
                if flask_thread.is_alive():
                     print("!!! WARNING: Flask thread did not stop cleanly.")

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
            print("--- Starting Network server threads (FTP & SSH) ---")
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
    print("--- Entered Keylogger view function ---") # Debug Print 1
    service_active = is_website_honeypot_active()
    attack_logs = []
    if service_active:
         print("--- Keylogger service is active, querying database... ---") # Debug Print 2
         attack_logs = AttackLog.objects.filter(source='Keylogger').order_by('-timestamp')[:200]
         print(f"--- Found {len(attack_logs)} Keylogger logs ---") # Debug Print 3
    else:
         print("--- Keylogger service is NOT active ---") # Debug Print 4
    context = {'active': 'Keylogger', 'attack_logs': attack_logs, 'source_name': 'Keylogger', 'service_is_active': service_active }
    return render(request, "network.html", context)

@login_required
def network(request):
    print("--- Entered network view function ---") # Debug Print 1
    service_active = is_network_honeypot_active()
    attack_logs = []
    if service_active:
         print("--- Network service is active, querying database... ---") # Debug Print 2
         attack_logs = AttackLog.objects.filter(source='Network').order_by('-timestamp')[:200]
         print(f"--- Found {len(attack_logs)} Network logs ---") # Debug Print 3
    else:
         print("--- Network service is NOT active ---") # Debug Print 4
    context = { 'active': 'network', 'attack_logs': attack_logs, 'source_name': 'Network Honeypot', 'service_is_active': service_active }
    return render(request, "network.html", context)

@login_required
def website(request):
    print("--- Entered website view function ---") # Debug Print 1
    service_active = is_website_honeypot_active()
    attack_logs = []
    if service_active:
         print("--- Website service is active, querying database... ---") # Debug Print 2
         attack_logs = AttackLog.objects.filter(source='Website').order_by('-timestamp')[:200]
         print(f"--- Found {len(attack_logs)} Website logs ---") # Debug Print 3
    else:
         print("--- Website service is NOT active ---") # Debug Print 4
    context = { 'active': 'website', 'attack_logs': attack_logs, 'source_name': 'Website Honeypot', 'service_is_active': service_active }
    return render(request, "network.html", context)


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
def handlelogout(request):
    logout(request)
    messages.info(request,"Logged out Successfully!")
    return redirect('handlelogin')