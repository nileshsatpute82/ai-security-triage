from flask import Flask, render_template, request, jsonify, session
import os
import json
import uuid
from datetime import datetime
from utils.bedrock_client import analyze_alerts_with_ai, investigate_incident_with_ai
from utils.alert_generator import generate_sample_alerts
from utils.crews import get_available_crews, get_crew_by_id

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# In-memory storage
conversations = {}
incidents = {}
investigations = {}

# Initialize some sample incidents
def init_sample_incidents():
    sample_incidents = [
        {
            'id': 'INC-20251101-001',
            'title': 'Application Layer DDoS',
            'description': 'High volume of requests detected targeting web application',
            'severity': 'Critical',
            'status': 'New',
            'created': datetime.now().isoformat(),
            'source': 'WAF Logs'
        },
        {
            'id': 'INC-20251101-002',
            'title': 'Suspicious Employee Activity',
            'description': 'Unusual API access patterns from internal user account',
            'severity': 'High',
            'status': 'New',
            'created': datetime.now().isoformat(),
            'source': 'CloudTrail'
        },
        {
            'id': 'INC-20251101-003',
            'title': 'Unauthorized Data Access',
            'description': 'Access to sensitive S3 bucket from unauthorized IP',
            'severity': 'High',
            'status': 'New',
            'created': datetime.now().isoformat(),
            'source': 'S3 Access Logs'
        },
        {
            'id': 'INC-20251101-004',
            'title': 'Privilege Abuse Detected',
            'description': 'Admin account used outside normal hours',
            'severity': 'Critical',
            'status': 'New',
            'created': datetime.now().isoformat(),
            'source': 'IAM Logs'
        }
    ]
    for incident in sample_incidents:
        incidents[incident['id']] = incident

init_sample_incidents()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/incidents')
def incidents_page():
    return render_template('incidents.html')

@app.route('/investigation/<incident_id>')
def investigation_page(incident_id):
    return render_template('investigation.html', incident_id=incident_id)

@app.route('/crews')
def crews_page():
    return render_template('crews.html')

@app.route('/chat')
def chat_page():
    return render_template('chat.html')

# API Endpoints
@app.route('/api/generate-alerts', methods=['POST'])
def generate_alerts():
    try:
        count = request.json.get('count', 10)
        alerts = generate_sample_alerts(count)
        return jsonify({'success': True, 'alerts': alerts, 'count': len(alerts)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/triage', methods=['POST'])
def triage_alerts():
    try:
        data = request.json
        alerts = data.get('alerts', [])
        user_query = data.get('query', '')
        session_id = data.get('session_id', str(uuid.uuid4()))
        
        if not alerts:
            return jsonify({'success': False, 'error': 'No alerts provided'}), 400
        
        context = conversations.get(session_id, {})
        ai_response = analyze_alerts_with_ai(alerts=alerts, user_query=user_query, context=context)
        
        conversations[session_id] = {
            'last_analysis': ai_response.get('summary', ''),
            'last_query': user_query,
            'timestamp': datetime.now().isoformat(),
            'alert_count': len(alerts)
        }
        
        return jsonify({'success': True, 'session_id': session_id, 'response': ai_response})
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/incidents', methods=['GET'])
def get_incidents():
    try:
        incidents_list = list(incidents.values())
        incidents_list.sort(key=lambda x: x['created'], reverse=True)
        return jsonify({'success': True, 'incidents': incidents_list})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/incidents/<incident_id>', methods=['GET'])
def get_incident(incident_id):
    try:
        incident = incidents.get(incident_id)
        if not incident:
            return jsonify({'success': False, 'error': 'Incident not found'}), 404
        return jsonify({'success': True, 'incident': incident})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/investigate/<incident_id>', methods=['POST'])
def investigate_incident(incident_id):
    try:
        incident = incidents.get(incident_id)
        if not incident:
            return jsonify({'success': False, 'error': 'Incident not found'}), 404
        
        # Start investigation
        investigation_id = f"INV-{incident_id}"
        
        # Use AI to investigate
        investigation_result = investigate_incident_with_ai(incident)
        
        investigations[investigation_id] = {
            'id': investigation_id,
            'incident_id': incident_id,
            'status': 'completed',
            'result': investigation_result,
            'timestamp': datetime.now().isoformat()
        }
        
        # Update incident status
        incidents[incident_id]['status'] = 'Investigating'
        
        return jsonify({
            'success': True,
            'investigation_id': investigation_id,
            'result': investigation_result
        })
    except Exception as e:
        print(f"Investigation error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/investigation/<investigation_id>', methods=['GET'])
def get_investigation(investigation_id):
    try:
        investigation = investigations.get(investigation_id)
        if not investigation:
            return jsonify({'success': False, 'error': 'Investigation not found'}), 404
        return jsonify({'success': True, 'investigation': investigation})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/crews', methods=['GET'])
def get_crews():
    try:
        crews = get_available_crews()
        return jsonify({'success': True, 'crews': crews})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/crews/<crew_id>', methods=['GET'])
def get_crew(crew_id):
    try:
        crew = get_crew_by_id(crew_id)
        if not crew:
            return jsonify({'success': False, 'error': 'Crew not found'}), 404
        return jsonify({'success': True, 'crew': crew})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/dashboard/stats', methods=['GET'])
def get_dashboard_stats():
    try:
        total_incidents = len(incidents)
        critical_count = sum(1 for i in incidents.values() if i['severity'] == 'Critical')
        high_count = sum(1 for i in incidents.values() if i['severity'] == 'High')
        
        stats = {
            'applications_tested': 83,
            'apps_tested_percentage': 83,
            'critical_vulnerabilities': critical_count,
            'dependency_coverage': 85,
            'projects_with_threat_models': 88,
            'total_incidents': total_incidents,
            'critical_incidents': critical_count,
            'high_incidents': high_count
        }
        return jsonify({'success': True, 'stats': stats})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
