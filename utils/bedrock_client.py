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

def call_bedrock_with_fallback(bedrock, prompt):
    """Try multiple model IDs until one works"""
    model_ids = [
        "anthropic.claude-3-5-sonnet-20240620-v1:0",
        "anthropic.claude-3-sonnet-20240229-v1:0",
        "anthropic.claude-v2:1",
    ]
    
    for model_id in model_ids:
        try:
            print(f"Trying model: {model_id}")
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
            print(f"✅ Successfully used model: {model_id}")
            return ai_text.strip()
            
        except Exception as e:
            print(f"Error with {model_id}: {e}")
            continue
    
    raise Exception("Unable to connect to any AI model")

def clean_json_response(text):
    """Remove markdown code blocks from JSON"""
    text = text.strip()
    text = re.sub(r'^```json\s*', '', text)
    text = re.sub(r'^```\s*', '', text)
    text = re.sub(r'\s*```$', '', text)
    return text.strip()

def analyze_alerts_with_ai(alerts, user_query='', context=None):
    """Analyze security alerts using AI"""
    bedrock = get_bedrock_client()
    prompt = build_triage_prompt(alerts, user_query, context or {})
    
    ai_text = call_bedrock_with_fallback(bedrock, prompt)
    ai_text = clean_json_response(ai_text)
    
    try:
        return json.loads(ai_text)
    except json.JSONDecodeError as e:
        print(f"JSON Parse Error: {e}")
        print(f"AI Response: {ai_text[:500]}")
        return {
            'summary': 'Analysis completed but response format was unexpected',
            'triaged_alerts': [],
            'critical_count': 0,
            'recommended_actions': ['Review alerts manually']
        }

def investigate_incident_with_ai(incident):
    """Automated investigation using AI"""
    bedrock = get_bedrock_client()
    prompt = build_investigation_prompt(incident)
    
    ai_text = call_bedrock_with_fallback(bedrock, prompt)
    ai_text = clean_json_response(ai_text)
    
    try:
        return json.loads(ai_text)
    except json.JSONDecodeError as e:
        print(f"JSON Parse Error in investigation: {e}")
        print(f"AI Response: {ai_text[:500]}")
        # Return a structured response even if JSON parsing fails
        return {
            'investigation_summary': ai_text[:500] if ai_text else 'Investigation completed',
            'findings': [],
            'timeline': [],
            'root_cause': 'Unable to parse detailed analysis',
            'impact_assessment': 'Please review manually',
            'recommended_actions': [
                {'priority': 'HIGH', 'action': 'Review incident manually', 'rationale': 'AI analysis format error'}
            ],
            'mitre_attack': {'tactic': 'Unknown', 'technique': 'Unknown', 'description': 'Analysis pending'},
            'false_positive_assessment': {'likelihood': 'MEDIUM', 'reasoning': 'Requires manual review'},
            'next_steps': ['Manual investigation required']
        }

def chat_with_bedrock(user_message, context=None):
    """Chat with AI Security Analyst"""
    bedrock = get_bedrock_client()
    
    # Build chat prompt
    if context and context.get('last_message'):
        prompt = f"""You are an expert AI Security Analyst assistant.

Previous conversation:
User: {context.get('last_message')}
You: {context.get('last_response')}

Current user question:
{user_message}

Provide a helpful, detailed response about cybersecurity. Be conversational but professional.
If discussing threats or vulnerabilities, provide actionable advice.
Keep your response clear and concise (2-4 paragraphs).
Do NOT use markdown formatting - just plain text with line breaks."""
    else:
        prompt = f"""You are an expert AI Security Analyst assistant.

User question:
{user_message}

Provide a helpful, detailed response about cybersecurity. Be conversational but professional.
If discussing threats or vulnerabilities, provide actionable advice.
Keep your response clear and concise (2-4 paragraphs).
Do NOT use markdown formatting - just plain text with line breaks."""
    
    try:
        response_text = call_bedrock_with_fallback(bedrock, prompt)
        return response_text
    except Exception as e:
        print(f"Chat error: {e}")
        return f"I apologize, but I encountered an error: {str(e)}. This may be due to API rate limits. Please try again in a moment."

def build_triage_prompt(alerts, user_query, context):
    """Build prompt for alert triage"""
    return f"""You are a security analyst AI.

CONTEXT: {json.dumps(context, indent=2) if context else "First analysis"}
ALERTS: {json.dumps(alerts, indent=2)}
USER QUERY: {user_query or "Analyze and prioritize"}

Respond with ONLY valid JSON (no markdown):
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
    """Build prompt for incident investigation"""
    return f"""You are an AI Security Analyst investigating an incident.

INCIDENT:
ID: {incident['id']}
Title: {incident['title']}
Description: {incident['description']}
Severity: {incident['severity']}
Source: {incident['source']}

Perform a detailed investigation. Respond with ONLY valid JSON (no markdown):
{{
    "investigation_summary": "2-3 sentence summary",
    "findings": [
        {{
            "title": "Finding title",
            "severity": "CRITICAL|HIGH|MEDIUM|LOW",
            "description": "Description",
            "evidence": "Evidence"
        }}
    ],
    "timeline": [
        {{
            "timestamp": "2025-11-01T10:30:00Z",
            "event": "What happened",
            "significance": "Why it matters"
        }}
    ],
    "root_cause": "Root cause analysis",
    "impact_assessment": "What was affected",
    "recommended_actions": [
        {{
            "priority": "IMMEDIATE|HIGH|MEDIUM",
            "action": "Specific action",
            "rationale": "Why this is needed"
        }}
    ],
    "mitre_attack": {{
        "tactic": "Tactic name",
        "technique": "Technique ID",
        "description": "How it maps"
    }},
    "false_positive_assessment": {{
        "likelihood": "HIGH|MEDIUM|LOW",
        "reasoning": "Assessment reasoning"
    }},
    "next_steps": ["Step 1", "Step 2", "Step 3"]
}}"""
