import os
import json
import uuid
from datetime import datetime
from dotenv import load_dotenv
from groq import Groq
import database

# Load .env file
load_dotenv()

DEFAULT_MODEL = "openai/gpt-oss-120b"
AVAILABLE_MODELS = [
    "openai/gpt-oss-120b",
    "openai/gpt-oss-20b",
    "groq/compound",
    "qwen/qwen3.8-27b",
    "llama-3.3-70b-versatile"
]

def get_groq_client():
    # 1. Check database setting
    db_key = database.get_setting("groq_api_key")
    if db_key and db_key.strip():
        return Groq(api_key=db_key.strip())
    
    # 2. Check environment variable
    env_key = os.environ.get("GROQ_API_KEY")
    if env_key and env_key.strip():
        return Groq(api_key=env_key.strip())
    
    return None

def is_groq_configured():
    client = get_groq_client()
    return client is not None

def generate_incident_report(event_id, model_name=None):
    """
    Generates a detailed, readable security analysis report for a selected event using Groq API.
    """
    event = database.get_event_by_id(event_id)
    if not event:
        raise ValueError(f"Event with ID {event_id} not found.")

    # Check existing report first
    existing = database.get_report_by_event_id(event_id)
    if existing:
        return existing

    client = get_groq_client()
    if not client:
        # Fallback response if no Groq API Key is configured yet
        report_id = f"RPT-{uuid.uuid4().hex[:8].upper()}"
        dummy_markdown = f"""# ⚠️ Security Incident Report (Groq API Key Required)

> **Note**: A valid Groq API Key is required to produce live LLM AI incident reports. Please configure your API key in the Dashboard Settings.

## 1. Incident Overview
* **Event ID**: `{event['event_id']}`
* **Title**: {event['title']}
* **Severity**: `{event['severity']}`
* **Category**: {event['category']}
* **Source IP**: `{event.get('source_ip', 'N/A')}`
* **Target User**: `{event.get('target_user', 'N/A')}`
* **Timestamp**: {event['timestamp']}

## 2. Telemetry Details
```json
{json.dumps(event.get('details', {}), indent=2)}
```

## 3. Recommended Actions
1. Configure `GROQ_API_KEY` in settings.
2. Isolate host `{event.get('source_ip', 'N/A')}` if malicious.
"""
        database.insert_ai_report(
            report_id=report_id,
            event_id=event_id,
            model_used="Fallback-Template",
            summary=f"Incident Report for {event['title']} (API Key Required)",
            mitre_attack=event.get('details', {}).get('mitre_attack', 'T1082'),
            content_markdown=dummy_markdown
        )
        return database.get_report_by_id(report_id)

    selected_model = model_name or database.get_setting("groq_model") or DEFAULT_MODEL

    system_prompt = """You are a Senior Security Operations Center (SOC) Lead Analyst and Digital Forensics Incident Response (DFIR) Specialist.
Your task is to generate a comprehensive, highly readable, actionable Security Incident Report based on the provided log telemetry and event data.

Structure your response clearly using GitHub-flavored Markdown with the following exact section headers:

# Security Incident Analysis Report

> **Incident ID**: [ID] | **Severity**: [CRITICAL/HIGH/MEDIUM/LOW] | **Status**: Investigated

## 1. Executive Summary
Provide a high-level concise summary of what occurred, the intent of the threat actor, and immediate risk assessment.

## 2. Threat Classification & MITRE ATT&CK Mapping
- **MITRE ATT&CK Technique**: ID & Name
- **Tactics**: e.g., Initial Access, Credential Access, Execution, Persistence
- **Threat Vector & Category**: Details

## 3. Deep Telemetry & Technical Analysis
Analyze the raw log payload, suspicious flags, command strings, or IP reputation details. Explain step-by-step how the attack was executed.

## 4. Impact Assessment & Blast Radius
Detail potential damage: data leakage, system compromise, lateral movement, or service degradation.

## 5. Incident Response & Containment Plan (Step-by-Step)
List immediate triage commands, firewall rules, IP blocking, service restarts, or credential resets required.

## 6. Security Posture & Detection Tuning Recommendations
Provide suggestions on how to improve SIEM rules, endpoint detection (EDR), or firewall policies to block similar attacks in the future.
"""

    user_prompt = f"""Generate an incident analysis report for the following security event:

Event ID: {event['event_id']}
Title: {event['title']}
Severity: {event['severity']}
Category: {event['category']}
Timestamp: {event['timestamp']}
Source IP: {event.get('source_ip', 'N/A')}
Target User: {event.get('target_user', 'N/A')}
Description: {event['description']}

Technical Details & Log Snippet:
{json.dumps(event.get('details', {}), indent=2)}
"""

    try:
        response = client.chat.completions.create(
            model=selected_model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.2,
            max_tokens=2048
        )
        report_markdown = response.choices[0].message.content

        # Extract summary snippet
        summary_line = f"AI Incident Analysis for {event['title']} ({event['severity']})"
        mitre_tag = event.get('details', {}).get('mitre_attack', 'T1082 - Security Assessment')

        report_id = f"RPT-{uuid.uuid4().hex[:8].upper()}"
        database.insert_ai_report(
            report_id=report_id,
            event_id=event_id,
            model_used=selected_model,
            summary=summary_line,
            mitre_attack=mitre_tag,
            content_markdown=report_markdown
        )
        return database.get_report_by_id(report_id)

    except Exception as e:
        print(f"[Groq API Error] {e}")
        # In case of API rate limit or key error
        report_id = f"RPT-{uuid.uuid4().hex[:8].upper()}"
        error_markdown = f"""# ⚠️ Security Incident Report Generation Error

> **Groq API Call Error**: `{str(e)}`

## Event Summary
* **Event ID**: `{event['event_id']}`
* **Title**: {event['title']}
* **Severity**: `{event['severity']}`
* **Category**: {event['category']}
* **Source IP**: `{event.get('source_ip')}`

Please check your Groq API key and rate limits in settings.
"""
        database.insert_ai_report(
            report_id=report_id,
            event_id=event_id,
            model_used=selected_model,
            summary=f"Report Generation Failed: {str(e)[:60]}",
            mitre_attack=event.get('details', {}).get('mitre_attack', 'N/A'),
            content_markdown=error_markdown
        )
        return database.get_report_by_id(report_id)


def query_soc_assistant(user_query, chat_history=None, model_name=None):
    """
    Interactive AI SOC Security Assistant query handler.
    Feeds system context (recent threats, stats, events) into prompt.
    """
    client = get_groq_client()
    
    # Gather live context from database
    metrics = database.get_soc_metrics()
    recent_events = database.get_recent_events(limit=10)
    
    context_str = f"""CURRENT REAL-TIME SOC STATUS:
- Total Ingested Logs: {metrics['total_logs']}
- Total Security Events Detected: {metrics['total_events']}
- Critical Severity Events: {metrics['critical_events']}
- High Severity Events: {metrics['high_events']}

RECENT DETECTED SECURITY EVENTS (Last 10):
"""
    for ev in recent_events:
        context_str += f"- [{ev['severity']}] {ev['event_id']}: {ev['title']} from IP {ev.get('source_ip', 'N/A')} ({ev['timestamp']})\n"

    system_prompt = f"""You are Choco 🍫, a cute, highly intelligent, friendly AI Security Analyst co-pilot and mascot embedded in a real-time Security Operations Center (SOC) dashboard.
Your job is to assist security analysts in querying live logs, understanding threats, analyzing suspicious IP addresses/users, and drafting containment scripts or incident response procedures.

{context_str}

Guidelines for Choco:
1. Introduce yourself warmly as Choco 🍫 when appropriate.
2. Provide concise, professional, expert threat-focused answers with a friendly, helpful tone.
3. Use cute security emojis (🍫, 🛡️, 🔍, ✨, ⚡) to make technical reports readable and engaging.
4. If the user asks about a specific IP, event ID, or threat, refer to the live context provided above or guide them step-by-step.
5. When writing response scripts (PowerShell, Bash, Python, Firewall rules), make them copy-paste ready and clean.
"""

    if not client:
        return {
            "answer": "⚠️ **Groq API Key Not Configured**: Please configure your Groq API Key in the **Settings** modal at the top right of the dashboard to enable full AI interactive queries.\n\n*Current System Status*:\n- Total Ingested Logs: " + str(metrics['total_logs']) + "\n- Active Security Events: " + str(metrics['total_events']) + "\n- Critical Threats: " + str(metrics['critical_events']),
            "model_used": "Offline-Fallback"
        }

    selected_model = model_name or database.get_setting("groq_model") or DEFAULT_MODEL

    messages = [{"role": "system", "content": system_prompt}]
    
    if chat_history:
        for msg in chat_history[-6:]:
            role = "assistant" if msg.get("sender") == "assistant" else "user"
            messages.append({"role": role, "content": msg.get("text", "")})
            
    messages.append({"role": "user", "content": user_query})

    try:
        response = client.chat.completions.create(
            model=selected_model,
            messages=messages,
            temperature=0.3,
            max_tokens=1500
        )
        return {
            "answer": response.choices[0].message.content,
            "model_used": selected_model
        }
    except Exception as e:
        return {
            "answer": f"⚠️ **Groq API Error**: `{str(e)}`. Please verify your API key in dashboard settings.",
            "model_used": selected_model
        }
