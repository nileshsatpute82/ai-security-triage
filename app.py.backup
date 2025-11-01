from flask import Flask, render_template, request, jsonify, session
import os
import json
import uuid
from datetime import datetime
from utils.bedrock_client import analyze_alerts_with_ai
from utils.alert_generator import generate_sample_alerts

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
conversations = {}

@app.route('/')
def index():
    return render_template('index.html')

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

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
