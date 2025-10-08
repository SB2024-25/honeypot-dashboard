import random
from django.core.management.base import BaseCommand
from faker import Faker
from attack_simulator.models import AttackLog

class Command(BaseCommand):
    help = 'Generates a specified number of fake attack logs'

    def add_arguments(self, parser):
        parser.add_argument('count', type=int, help='The number of attack logs to create')

    def handle(self, *args, **kwargs):
        count = kwargs['count']
        fake = Faker()
        
        attack_types = [choice[0] for choice in AttackLog.ATTACK_TYPE_CHOICES]
        sources = [choice[0] for choice in AttackLog.SOURCE_CHOICES]
        
        logs = []
        for _ in range(count):
            # --- THIS IS THE MISSING LOGIC THAT NEEDS TO BE ADDED BACK ---
            # 80% chance for a malicious location, 20% for a less common one
            if random.random() < 0.8:
                location = random.choice(['China', 'Russia', 'USA', 'North Korea', 'Iran'])
            else:
                location = fake.country()
            # -----------------------------------------------------------

            log = AttackLog(
                ip_address=fake.ipv4(),
                location=location, # Now this variable is defined
                attack_type=random.choice(attack_types),
                source=random.choice(sources)
            )
            logs.append(log)

        AttackLog.objects.bulk_create(logs)
        
        self.stdout.write(self.style.SUCCESS(f'Successfully created {count} attack logs.'))