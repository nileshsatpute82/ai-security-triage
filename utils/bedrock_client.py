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
    
    # Try these model IDs in order until one works
    model_ids = [
        "anthropic.claude-3-5-sonnet-20240620-v1:0",  # Claude 3.5 Sonnet (most common)
        "anthropic.claude-3-sonnet-20240229-v1:0",    # Claude 3 Sonnet
        "anthropic.claude-v2:1",                       # Claude 2.1 (fallback)
    ]
    
    last_error = None
    
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
            
            # Clean up the response - remove markdown code blocks
            ai_text = ai_text.strip()
            ai_text = re.sub(r'^```json\s*', '', ai_text)
            ai_text = re.sub(r'^```\s*', '', ai_text)
            ai_text = re.sub(r'\s*```$', '', ai_text)
            ai_text = ai_text.strip()
            
            try:
                ai_analysis = json.loads(ai_text)
                print(f"✅ Successfully used model: {model_id}")
                return ai_analysis
            except json.JSONDecodeError as e:
                print(f"JSON Parse Error with {model_id}: {e}")
                print(f"AI Response: {ai_text[:500]}")
                # Try next model
                continue
                
        except Exception as e:
            print(f"Error with model {model_id}: {str(e)}")
            last_error = str(e)
            continue
    
    # If all models failed, return error response
    return {
        'summary': f'Unable to connect to any Claude model. Last error: {last_error}',
        'triaged_alerts': [],
        'critical_count': 0,
        'high_count': 0,
        'false_positive_count': 0,
        'top_3_critical': ['Bedrock connection failed - check model access'],
        'recommended_actions': [
            'Go to AWS Bedrock console',
            'Click "Model access"',
            'Enable access to Claude 3.5 Sonnet',
            'Wait 1-2 minutes for activation'
        ],
        'questions_for_analyst': [],
        'ai_dlc_notes': f'Error: {last_error}'
    }

def build_triage_prompt(alerts, user_query, context):
    return f"""You are a security analyst AI using AI-DLC methodology.

CONTEXT: {json.dumps(context, indent=2) if context else "First analysis"}
ALERTS: {json.dumps(alerts, indent=2)}
USER QUERY: {user_query or "Analyze and prioritize these alerts"}

Analyze for risk, prioritize, provide plain-English explanations.

CRITICAL: Respond with ONLY valid JSON. No markdown, no code blocks, no text outside JSON.

{{
    "summary": "Brief overview (2-3 sentences)",
    "critical_count": 0,
    "high_count": 0,
    "false_positive_count": 0,
    "triaged_alerts": [
        {{
            "alert_id": "ID",
            "original_severity": "SEVERITY",
            "ai_priority": "CRITICAL|HIGH|MEDIUM|LOW",
            "confidence": 0.95,
            "plain_english_explanation": "What this means",
            "threat_type": "Type",
            "business_impact": "Impact",
            "false_positive_likelihood": "HIGH|MEDIUM|LOW",
            "immediate_actions": ["Action 1"],
            "evidence": "Indicators"
        }}
    ],
    "top_3_critical": ["Alert 1", "Alert 2", "Alert 3"],
    "recommended_actions": ["Action 1", "Action 2"],
    "questions_for_analyst": ["Question"],
    "ai_dlc_notes": "Context saved"
}}

Respond with ONLY the JSON object. No markdown code blocks."""
