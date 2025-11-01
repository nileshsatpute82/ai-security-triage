import boto3
import json
import os

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
    
    try:
        response = bedrock.invoke_model(
            modelId="anthropic.claude-sonnet-4-5-20250929-v1:0",
            body=json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 4096,
                "temperature": 0.3,
                "messages": [{"role": "user", "content": prompt}]
            })
        )
        
        response_body = json.loads(response['body'].read())
        ai_text = response_body['content'][0]['text']
        
        try:
            ai_analysis = json.loads(ai_text)
        except:
            ai_analysis = {'summary': ai_text, 'triaged_alerts': [], 'critical_count': 0, 'recommendations': ['Review manually']}
        
        return ai_analysis
    except Exception as e:
        raise Exception(f"AI analysis failed: {str(e)}")

def build_triage_prompt(alerts, user_query, context):
    return f"""You are a security analyst AI using AI-DLC methodology.

CONTEXT: {json.dumps(context, indent=2) if context else "First analysis"}
ALERTS: {json.dumps(alerts, indent=2)}
USER QUERY: {user_query or "Analyze and prioritize these alerts"}

Analyze for risk, prioritize, provide plain-English explanations.

RESPOND WITH VALID JSON ONLY:
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
}}"""
