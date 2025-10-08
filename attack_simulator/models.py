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

    def __str__(self):
        return f'{self.get_attack_type_display()} from {self.ip_address} via {self.get_source_display()}'