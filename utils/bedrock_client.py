import boto3
import json
import os
import re

def get_bedrock_client():
    return boto3.client(
        'bedrock-runtime',
        region_name=os.environ.get('AWS_REGION', 'us-east-1'),
        aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY')
    )

def analyze_alerts_with_ai(alerts, user_query='', context=None):
    bedrock = get_bedrock_client()
    prompt = build_triage_prompt(alerts, user_query, context or {})
    return call_bedrock_with_fallback(bedrock, prompt)

def investigate_incident_with_ai(incident):
    """Automated investigation using AI"""
    bedrock = get_bedrock_client()
    prompt = build_investigation_prompt(incident)
    return call_bedrock_with_fallback(bedrock, prompt)

def call_bedrock_with_fallback(bedrock, prompt):
    model_ids = [
        "anthropic.claude-3-5-sonnet-20240620-v1:0",
        "anthropic.claude-3-sonnet-20240229-v1:0",
        "anthropic.claude-v2:1",
    ]
    
    for model_id in model_ids:
        try:
            response = bedrock.invoke_model(
                modelId=model_id,
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 4096,
                    "temperature": 0.3,
                    "messages": [{"role": "user", "content": prompt}]
                })
            )
            
            response_body = json.loads(response['body'].read())
            ai_text = response_body['content'][0]['text']
            ai_text = clean_json_response(ai_text)
            
            try:
                return json.loads(ai_text)
            except:
                continue
        except Exception as e:
            print(f"Error with {model_id}: {e}")
            continue
    
    return create_error_response("Unable to connect to AI model")

def clean_json_response(text):
    text = text.strip()
    text = re.sub(r'^```json\s*', '', text)
    text = re.sub(r'^```\s*', '', text)
    text = re.sub(r'\s*```$', '', text)
    return text.strip()

def build_triage_prompt(alerts, user_query, context):
    return f"""You are a security analyst AI using AI-DLC methodology.

CONTEXT: {json.dumps(context, indent=2) if context else "First analysis"}
ALERTS: {json.dumps(alerts, indent=2)}
USER QUERY: {user_query or "Analyze and prioritize"}

Respond with ONLY valid JSON:
{{
    "summary": "Brief overview",
    "critical_count": 0,
    "high_count": 0,
    "false_positive_count": 0,
    "triaged_alerts": [
        {{
            "alert_id": "ID",
            "original_severity": "SEVERITY",
            "ai_priority": "CRITICAL|HIGH|MEDIUM|LOW",
            "confidence": 0.95,
            "plain_english_explanation": "Explanation",
            "threat_type": "Type",
            "business_impact": "Impact",
            "false_positive_likelihood": "HIGH|MEDIUM|LOW",
            "immediate_actions": ["Action"],
            "evidence": "Evidence"
        }}
    ],
    "top_3_critical": ["Alert 1", "Alert 2", "Alert 3"],
    "recommended_actions": ["Action 1", "Action 2"],
    "questions_for_analyst": ["Question"],
    "ai_dlc_notes": "Context saved"
}}"""

def build_investigation_prompt(incident):
    return f"""You are an AI Security Analyst investigating a security incident.

INCIDENT:
ID: {incident['id']}
Title: {incident['title']}
Description: {incident['description']}
Severity: {incident['severity']}
Source: {incident['source']}

Perform a detailed investigation and provide results in JSON format:
{{
    "investigation_summary": "2-3 sentence summary of findings",
    "findings": [
        {{
            "title": "Finding title",
            "severity": "CRITICAL|HIGH|MEDIUM|LOW",
            "description": "Detailed description",
            "evidence": "Supporting evidence"
        }}
    ],
    "timeline": [
        {{
            "timestamp": "ISO timestamp",
            "event": "What happened",
            "significance": "Why it matters"
        }}
    ],
    "root_cause": "Root cause analysis",
    "impact_assessment": "What systems/data were affected",
    "recommended_actions": [
        {{
            "priority": "IMMEDIATE|HIGH|MEDIUM",
            "action": "Specific action to take",
            "rationale": "Why this action is needed"
        }}
    ],
    "mitre_attack": {{
        "tactic": "Tactic name",
        "technique": "Technique ID and name",
        "description": "How it maps to MITRE"
    }},
    "false_positive_assessment": {{
        "likelihood": "HIGH|MEDIUM|LOW",
        "reasoning": "Why this may or may not be a false positive"
    }},
    "next_steps": ["Step 1", "Step 2", "Step 3"]
}}

Be thorough and provide actionable intelligence."""

def create_error_response(error_message):
    return {
        'summary': error_message,
        'triaged_alerts': [],
        'critical_count': 0,
        'recommended_actions': ['Check AWS Bedrock access', 'Verify credentials']
    }
