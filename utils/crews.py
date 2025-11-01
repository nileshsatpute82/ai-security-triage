"""
Specialized AI Crews for different security domains
Each crew is an AI agent specialized in a specific area
"""

def get_available_crews():
    return [
        {
            'id': 'container-security-01',
            'name': 'Container Security Crew',
            'description': 'Kubernetes and Docker security analysis',
            'capabilities': ['Container scanning', 'K8s misconfigurations', 'Image vulnerabilities'],
            'status': 'active'
        },
        {
            'id': 'authorization-01',
            'name': 'Authorization Security Crew',
            'description': 'IAM and access control analysis',
            'capabilities': ['Permission analysis', 'Role review', 'Access patterns'],
            'status': 'active'
        },
        {
            'id': 'cloud-security-01',
            'name': 'Cloud Security Crew',
            'description': 'AWS/Azure/GCP security posture',
            'capabilities': ['Cloud config review', 'Security groups', 'Network analysis'],
            'status': 'active'
        },
        {
            'id': 'authentication-01',
            'name': 'Authentication Security Crew',
            'description': 'Authentication and identity security',
            'capabilities': ['Auth bypass detection', 'MFA analysis', 'Session management'],
            'status': 'active'
        },
        {
            'id': 'audit-compliance-01',
            'name': 'Audit & Compliance Crew',
            'description': 'Compliance checking and audit support',
            'capabilities': ['SOC2 compliance', 'GDPR checks', 'Audit trails'],
            'status': 'active'
        },
        {
            'id': 'appsec-001',
            'name': 'Application Security Crew',
            'description': 'OWASP Top 10 and app vulnerabilities',
            'capabilities': ['SAST/DAST analysis', 'Code review', 'Web app security'],
            'status': 'active'
        },
        {
            'id': 'ai-security-001',
            'name': 'AI Security Crew',
            'description': 'AI/ML model security and adversarial attacks',
            'capabilities': ['Model poisoning detection', 'Prompt injection', 'AI risk assessment'],
            'status': 'active'
        }
    ]

def get_crew_by_id(crew_id):
    crews = get_available_crews()
    for crew in crews:
        if crew['id'] == crew_id:
            return crew
    return None
