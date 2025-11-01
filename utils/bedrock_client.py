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
        
        # Clean up the response - remove markdown code blocks
        ai_text = ai_text.strip()
        # Remove ```json and ``` markers
        ai_text = re.sub(r'^```json\s*', '', ai_text)
        ai_text = re.sub(r'^```\s*', '', ai_text)
        ai_text = re.sub(r'\s*```$', '', ai_text)
        ai_text = ai_text.strip()
        
        try:
            ai_analysis = json.loads(ai_text)
        except json.JSONDecodeError as e:
            print(f"JSON Parse Error: {e}")
            print(f"AI Response: {ai_text[:500]}")  # Log first 500 chars
            # Fallback response
            ai_analysis = {
                'summary': 'AI analysis completed but response format was unexpected. Please check logs.',
                'triaged_alerts': [],
                'critical_count': 0,
                'high_count': 0,
                'false_positive_count': 0,
                'top_3_critical': ['Unable to parse AI response'],
                'recommended_actions': ['Check application logs', 'Verify Bedrock access'],
                'questions_for_analyst': [],
                'ai_dlc_notes': f'Error: {str(e)}'
            }
        
        return ai_analysis
        
    except Exception as e:
        print(f"Bedrock error: {str(e)}")
        # Return a user-friendly error
        return {
            'summary': f'Error connecting to AWS Bedrock: {str(e)}',
            'triaged_alerts': [],
            'critical_count': 0,
            'high_count': 0,
            'false_positive_count': 0,
            'top_3_critical': ['Bedrock connection failed'],
            'recommended_actions': ['Check AWS credentials', 'Verify Bedrock access in region', 'Check IAM permissions'],
            'questions_for_analyst': [],
            'ai_dlc_notes': f'Bedrock API Error: {str(e)}'
        }

def build_triage_prompt(alerts, user_query, context):
    return f"""You are a security analyst AI using AI-DLC methodology.

CONTEXT: {json.dumps(context, indent=2) if context else "First analysis"}
ALERTS: {json.dumps(alerts, indent=2)}
USER QUERY: {user_query or "Analyze and prioritize these alerts"}

Analyze for risk, prioritize, provide plain-English explanations.

CRITICAL: You MUST respond with ONLY valid JSON. No markdown, no code blocks, no explanations outside the JSON.

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

Respond with ONLY the JSON object above. Do not wrap it in markdown code blocks."""
