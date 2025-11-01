import random
from datetime import datetime, timedelta

def generate_sample_alerts(count=10):
    templates = [
        {'type': 'GuardDuty', 'severity': 'HIGH', 'title': 'UnauthorizedAccess:EC2/SSHBruteForce', 
         'description': 'SSH brute force from {ip} to {instance}', 'source': 'AWS GuardDuty'},
        {'type': 'GuardDuty', 'severity': 'CRITICAL', 'title': 'Backdoor:EC2/C&CActivity', 
         'description': 'Instance {instance} querying malware domain', 'source': 'AWS GuardDuty'},
        {'type': 'CloudTrail', 'severity': 'MEDIUM', 'title': 'Unusual API Activity', 
         'description': 'User {user} made {count} unusual API calls', 'source': 'AWS CloudTrail'},
        {'type': 'SecurityHub', 'severity': 'HIGH', 'title': 'IAM Excessive Permissions', 
         'description': 'User {user} has admin access', 'source': 'AWS Security Hub'},
        {'type': 'GuardDuty', 'severity': 'CRITICAL', 'title': 'Trojan:EC2/BlackholeTraffic', 
         'description': 'Instance {instance} communicating with blackhole DNS', 'source': 'AWS GuardDuty'},
        {'type': 'CloudTrail', 'severity': 'HIGH', 'title': 'Root Account Usage', 
         'description': 'Root account used to modify security', 'source': 'AWS CloudTrail'}
    ]
    
    alerts = []
    for i in range(count):
        template = random.choice(templates)
        alerts.append({
            'alert_id': f'ALERT-{datetime.now().strftime("%Y%m%d")}-{random.randint(1000, 9999)}',
            'timestamp': (datetime.now() - timedelta(minutes=random.randint(1, 1440))).isoformat(),
            'type': template['type'],
            'severity': template['severity'],
            'title': template['title'],
            'description': template['description'].format(
                ip=f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                instance=f"i-{random.randint(10000000, 99999999):08x}",
                user=random.choice(['john.doe', 'admin', 'service-account']),
                count=random.randint(50, 500)
            ),
            'source': template['source'],
            'resource': f"arn:aws:ec2:us-east-1:123456789012:instance/i-{random.randint(10000000, 99999999):08x}",
            'account_id': '123456789012',
            'region': random.choice(['us-east-1', 'us-west-2', 'eu-west-1'])
        })
    
    alerts.sort(key=lambda x: x['timestamp'], reverse=True)
    return alerts
