# attack_simulator/models.py
from django.db import models

class AttackLog(models.Model):
    # --- EXPANDED ATTACK TYPES (Corrected List) ---
    ATTACK_TYPE_CHOICES = [
        # Common Web Attacks
        ('SQLI', 'SQL Injection'),
        ('XSS', 'Cross-Site Scripting'),
        ('CSRF', 'Cross-Site Request Forgery'),
        ('DIR_TRAV', 'Directory Traversal'),
        ('CMD_INJ', 'Command Injection'),
        ('FILE_INC', 'File Inclusion'),
        ('XXE', 'XML External Entity'),
        # Common Network Attacks
        ('BRUTEFORCE', 'Brute Force'), # Applicable to many services
        ('PORTSCAN', 'Port Scan'),
        ('SNIFFING', 'Packet Sniffing'), # Simulation description
        ('MITM', 'Man-in-the-Middle'), # Simulation description
        ('RECON', 'Network Reconnaissance'),
        ('MALWARE_PROP', 'Malware Propagation'), # Simulation description
        # Common Endpoint/Keylogger Attacks
        ('KEYLOGGING', 'Keylogging'),
        ('CRED_HARVEST', 'Credential Harvesting'),
        ('DATA_EXFIL', 'Data Exfiltration'),
        ('SCREEN_CAP', 'Screen Capture'), # Simulation description
        # General / Other
        ('DDOS', 'DDoS'), # Can target web or network
        ('OTHER', 'Other Suspicious Activity'),
    ]

    # --- SOURCE CHOICES (Defined BEFORE use) ---
    SOURCE_CHOICES = [
        ('Network', 'Network Honeypot'),
        ('Website', 'Website Honeypot'),
        ('Keylogger', 'Keylogger'),
    ]

    # --- Model Fields ---
    ip_address = models.GenericIPAddressField()
    location = models.CharField(max_length=100)
    # Use the expanded choices and increased max_length
    attack_type = models.CharField(max_length=15, choices=ATTACK_TYPE_CHOICES) # Increased max_length
    timestamp = models.DateTimeField(auto_now_add=True)
    # Use the SOURCE_CHOICES defined above
    source = models.CharField(max_length=10, choices=SOURCE_CHOICES, default='Network')
    # Fields for specific attack details
    captured_data = models.CharField(max_length=255, blank=True, null=True, help_text="Description or data related to the attack.")
    target_context = models.CharField(max_length=100, blank=True, null=True, help_text="The field, service, or area targeted.")

    # String representation for admin and logs
    def __str__(self):
        return f'{self.get_attack_type_display()} from {self.ip_address} via {self.get_source_display()}'
    