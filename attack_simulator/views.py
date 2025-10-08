import threading
import time
import random
from django.shortcuts import redirect, render
from django.contrib.auth import authenticate, login,logout
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from honeypot.Honeypot_Project_final import main
from werkzeug.serving import make_server
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json

from django.db.models import Count
from attack_simulator.models import AttackLog
from faker import Faker

# --- Global variables for tracking server state ---
flask_thread = None
flask_server = None
ftp_thread = None
ssh_thread = None

# --- Global variables for the attack generator thread ---
attack_generator_thread = None
generator_stop_event = threading.Event()

# --- HELPER FUNCTIONS (This is the part that was missing) ---
def is_website_honeypot_active():
    """Checks if the Flask (Website) honeypot thread is running."""
    return flask_thread is not None and flask_thread.is_alive()

def is_network_honeypot_active():
    """Checks if the FTP or SSH (Network) honeypot threads are running."""
    return (ftp_thread is not None and ftp_thread.is_alive()) or \
           (ssh_thread is not None and ssh_thread.is_alive())
# ----------------------------------------------------------------

# --- The function that runs in the background to generate attacks ---
def run_attack_generator(stop_event):
    """
    This function runs in a separate thread. It continuously generates attacks
    for the active honeypot services until the stop_event is set.
    """
    fake = Faker()
    attack_types = [choice[0] for choice in AttackLog.ATTACK_TYPE_CHOICES]
    
    # Lists of realistic fake data for our simulation
    common_usernames = ['admin', 'root', 'user', 'test', 'guest', 'administrator', 'backup']
    common_passwords = ['123456', 'password', '12345', 'qwerty', 'admin', 'root', '123456789']
    web_payloads = ["' OR 1=1 --", "<script>alert('XSS')</script>", "UNION SELECT null,null,null --"]
    web_paths = ["/admin", "/wp-login.php", "/.env", "/config.json", "/backup.zip"]

    while not stop_event.is_set():
        active_sources = []
        if is_website_honeypot_active():
            active_sources.append('Website')
            active_sources.append('Keylogger')
        if is_network_honeypot_active():
            active_sources.append('Network')

        if active_sources:
            source = random.choice(active_sources)
            
            log_data = {
                'ip_address': fake.ipv4(),
                'location': fake.country(),
                'attack_type': random.choice(attack_types),
                'source': source,
            }

            # Logic to generate data based on the attack source
            if source == 'Keylogger':
                log_data['attack_type'] = 'BruteForce'
                if random.choice([True, False]):
                    log_data['target_context'] = 'login_username_field'
                    log_data['captured_data'] = random.choice(common_usernames)
                else:
                    log_data['target_context'] = 'login_password_field'
                    log_data['captured_data'] = random.choice(common_passwords)

            elif source == 'Website':
                if random.choice([True, False]):
                    log_data['target_context'] = 'Search Bar'
                    log_data['captured_data'] = random.choice(web_payloads)
                    log_data['attack_type'] = random.choice(['SQLI', 'XSS'])
                else:
                    log_data['target_context'] = 'URL Path'
                    log_data['captured_data'] = random.choice(web_paths)
                    log_data['attack_type'] = 'PortScan'
            
            elif source == 'Network':
                log_data['target_context'] = random.choice(['SSH Login', 'FTP Login'])
                user = random.choice(common_usernames)
                pwd = random.choice(common_passwords)
                log_data['captured_data'] = f"user='{user}', pass='{pwd}'"
                log_data['attack_type'] = 'BruteForce'
            
            AttackLog.objects.create(**log_data)
        
        time.sleep(random.uniform(1, 3))


def handle_logs(LOG_FILE_PATH):
    logs = []
    try:
        with open(LOG_FILE_PATH, 'r') as file:
            for line in file:
                line = line.strip()
                if line:
                    logs.append(json.loads(line))
    except FileNotFoundError:
        pass
    return logs

@login_required
def dashboard(request):
    active_sources = []
    if is_website_honeypot_active():
        active_sources.append('Website')
        active_sources.append('Keylogger')
    if is_network_honeypot_active():
        active_sources.append('Network')

    if active_sources:
        latest_attacks = AttackLog.objects.filter(source__in=active_sources).order_by('-timestamp')[:50]
        total_attacks = AttackLog.objects.filter(source__in=active_sources).count()
        unique_attackers = AttackLog.objects.filter(source__in=active_sources).values('ip_address').distinct().count()
    else:
        latest_attacks, total_attacks, unique_attackers = [], 0, 0

    context = { "active": "dashboard", "services_active": bool(active_sources), "total_attacks": total_attacks, "unique_attackers": unique_attackers, "latest_attacks": latest_attacks }
    return render(request, 'dashboard.html', context)


def attack_type_data(request):
    active_sources = []
    if is_website_honeypot_active():
        active_sources.append('Website')
        active_sources.append('Keylogger')
    if is_network_honeypot_active():
        active_sources.append('Network')

    data = AttackLog.objects.filter(source__in=active_sources).values('attack_type').annotate(count=Count('attack_type')).order_by('-count') if active_sources else []
    
    attack_model = AttackLog()
    attack_type_mapping = dict(attack_model.ATTACK_TYPE_CHOICES)
    labels = [attack_type_mapping.get(item['attack_type'], item['attack_type']) for item in data]
    counts = [item['count'] for item in data]
    
    chart_data = { 'labels': labels, 'data': counts, }
    return JsonResponse(chart_data)

def get_new_attacks_api(request):
    latest_id = request.GET.get('latest_id', 0)
    
    active_sources = []
    if is_website_honeypot_active():
        active_sources.append('Website')
        active_sources.append('Keylogger')
    if is_network_honeypot_active():
        active_sources.append('Network')

    if active_sources:
        new_attacks = AttackLog.objects.filter(id__gt=latest_id, source__in=active_sources).order_by('-timestamp')
        data = list(new_attacks.values('id', 'timestamp', 'source', 'ip_address', 'location', 'attack_type', 'target_context', 'captured_data'))
        source_map = dict(AttackLog.SOURCE_CHOICES)
        type_map = dict(AttackLog.ATTACK_TYPE_CHOICES)
        for attack in data:
            attack['source_display'] = source_map.get(attack['source'])
            attack['attack_type_display'] = type_map.get(attack['attack_type'])
    else:
        data = []
        
    return JsonResponse({'attacks': data})

def start_generator_if_needed():
    global attack_generator_thread
    if attack_generator_thread is None or not attack_generator_thread.is_alive():
        generator_stop_event.clear()
        attack_generator_thread = threading.Thread(target=run_attack_generator, args=(generator_stop_event,))
        attack_generator_thread.start()

def stop_generator_if_idle():
    global attack_generator_thread
    if not is_website_honeypot_active() and not is_network_honeypot_active():
        if attack_generator_thread is not None and attack_generator_thread.is_alive():
            generator_stop_event.set()
            attack_generator_thread.join()
            attack_generator_thread = None

@csrf_exempt
def start_flask_server(request):
    global flask_thread, flask_server
    if request.method == 'POST':
        if not is_website_honeypot_active():
            def run_flask():
                global flask_server
                flask_server = make_server('0.0.0.0', 5000, main.WebsiteTrap.app, threaded=True)
                flask_server.serve_forever()

            flask_thread = threading.Thread(target=run_flask)
            flask_thread.start()
            start_generator_if_needed()
            return JsonResponse({'status': 'started', 'ip': '0.0.0.0', 'port': '5000'})
        else:
            return JsonResponse({'status': 'already_running'})
    return JsonResponse({'error': 'Invalid request method'}, status=400)

@csrf_exempt
def stop_flask_server(request):
    global flask_thread, flask_server
    if request.method == 'POST':
        if is_website_honeypot_active():
            flask_server.shutdown()
            flask_thread.join()
            flask_thread = None
            flask_server = None
            stop_generator_if_idle()
            return JsonResponse({'status': 'stopped'})
        else:
            return JsonResponse({'status': 'not_running'})
    return JsonResponse({'error': 'Invalid request method'}, status=400)

@csrf_exempt
def start_network_server(request):
    global ftp_thread, ssh_thread
    if request.method == 'POST':
        if not is_network_honeypot_active():
            ftp_thread = threading.Thread(target=main.FtpHoneypot.run_ftp_server)
            ftp_thread.start()
            ssh_thread = threading.Thread(target=main.SSHhoneypot.start_ssh_server)
            ssh_thread.start()
            start_generator_if_needed()
            return JsonResponse({'status': 'started'})
        else:
            return JsonResponse({'status': 'already_running'})
    return JsonResponse({'error': 'Invalid request method'}, status=400)

@csrf_exempt
def stop_network_server(request):
    global ftp_thread, ssh_thread
    if request.method == 'POST':
        if is_network_honeypot_active():
            main.FtpHoneypot.stop_ftp_server()
            main.SSHhoneypot.stop_ssh_server()
            if ftp_thread: ftp_thread.join(timeout=1.0)
            if ssh_thread: ssh_thread.join(timeout=1.0)
            ftp_thread = None
            ssh_thread = None
            stop_generator_if_idle()
        return JsonResponse({'status': 'stopped'})
    return JsonResponse({'error': 'Invalid request method'}, status=400)

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
    attack_logs = AttackLog.objects.filter(source='Keylogger').order_by('-timestamp') if service_active else []
    context = {'active': 'Keylogger', 'attack_logs': attack_logs, 'source_name': 'Keylogger', 'service_is_active': service_active }
    return render(request, "network.html", context)

@login_required
def network(request):
    service_active = is_network_honeypot_active()
    attack_logs = AttackLog.objects.filter(source='Network').order_by('-timestamp') if service_active else []
    context = { 'active': 'network', 'attack_logs': attack_logs, 'source_name': 'Network Honeypot', 'service_is_active': service_active }
    return render(request, "network.html", context)

@login_required
def website(request):
    service_active = is_website_honeypot_active()
    attack_logs = AttackLog.objects.filter(source='Website').order_by('-timestamp') if service_active else []
    context = { 'active': 'website', 'attack_logs': attack_logs, 'source_name': 'Website Honeypot', 'service_is_active': service_active }
    return render(request, "network.html", context)

def handlelogin(request):
    if request.method=="POST":
        Username=request.POST["loginusername"]
        Password=request.POST["loginpassword"]
        user=authenticate(username=Username,password=Password)
        if user is not None:
            login(request,user)
            return redirect("dashboard")
        else:
            messages.error(request,"Username or Password is incorrect.")
            return redirect('handlelogin')
    return render(request,'login.html')

@login_required
def handlelogout(request):
    logout(request)
    messages.info(request,"Logged out Successfully!")
    return redirect('handlelogin')