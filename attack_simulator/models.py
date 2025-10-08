# attack_simulator/models.py
from django.db import models

class AttackLog(models.Model):
    ATTACK_TYPE_CHOICES = [
        ('SQLI', 'SQL Injection'),
        ('DDoS', 'DDoS'),
        ('BruteForce', 'Brute Force'),
        ('PortScan', 'Port Scan'),
        ('XSS', 'Cross-Site Scripting'),
    ]
    
    # --- ADD THIS NEW FIELD ---
    SOURCE_CHOICES = [
        ('Network', 'Network Honeypot'),
        ('Website', 'Website Honeypot'),
        ('Keylogger', 'Keylogger'),
    ]
    # -------------------------

    ip_address = models.GenericIPAddressField()
    location = models.CharField(max_length=100)
    attack_type = models.CharField(max_length=10, choices=ATTACK_TYPE_CHOICES)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    # --- AND THIS LINE ---
    source = models.CharField(max_length=10, choices=SOURCE_CHOICES, default='Network')
    # --------------------
    
    from django.db import models

class AttackLog(models.Model):
    # This is the list of choices for the attack_type field
    ATTACK_TYPE_CHOICES = [
        ('SQLI', 'SQL Injection'),
        ('DDoS', 'DDoS'),
        ('BruteForce', 'Brute Force'),
        ('PortScan', 'Port Scan'),
        ('XSS', 'Cross-Site Scripting'),
    ]
    
    # --- THIS IS THE CORRECT PLACEMENT for SOURCE_CHOICES ---
    # It must be defined before the 'source' field below uses it.
    SOURCE_CHOICES = [
        ('Network', 'Network Honeypot'),
        ('Website', 'Website Honeypot'),
        ('Keylogger', 'Keylogger'),
    ]
    # -------------------------------------------------------------

    ip_address = models.GenericIPAddressField()
    location = models.CharField(max_length=100)
    attack_type = models.CharField(max_length=10, choices=ATTACK_TYPE_CHOICES)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    # This field now correctly uses the SOURCE_CHOICES list from above
    source = models.CharField(max_length=10, choices=SOURCE_CHOICES, default='Network')
    
    # These are the fields for the keylogger data
    captured_data = models.CharField(max_length=255, blank=True, null=True, help_text="The actual keystrokes or data captured.")
    target_context = models.CharField(max_length=100, blank=True, null=True, help_text="The field or area where data was captured (e.g., username field).")

    def __str__(self):
        return f'{self.get_attack_type_display()} from {self.ip_address} via {self.get_source_display()}'
