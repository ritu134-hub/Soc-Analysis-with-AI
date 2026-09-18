import re
import uuid
import json
from datetime import datetime

# Regex & heuristic detection rules
SQLI_PATTERNS = [
    r"(\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b.*?\b(FROM|INTO|TABLE|DATABASE)\b)",
    r"('|\")\s*OR\s*('1'='1'|1=1)",
    r"WAITFOR\s+DELAY\s+'",
    r"exec\(\s*char\("
]

XSS_PATTERNS = [
    r"<script[^>]*>",
    r"javascript\s*:",
    r"onerror\s*=\s*",
    r"onload\s*=\s*",
    r"<iframe[^>]*>"
]

SUSPICIOUS_COMMAND_PATTERNS = [
    r"powershell.*(-enc|-encodedcommand|-e\s)",
    r"powershell.*(-nop|-ExecutionPolicy\s+Bypass)",
    r"Invoke-Expression|IEX",
    r"DownloadString|DownloadFile",
    r"certutil.*-urlcache",
    r"vssadmin\s+delete\s+shadows",
    r"cmd\.exe\s+/c\s+whoami",
    r"net\s+user\s+.*\/add"
]

PRIVILEGE_ESCALATION_PATTERNS = [
    r"EventID:\s*(4720|4722|4728|4732)", # Account creation / Group elevation
    r"sudoers\s+modified",
    r"runas\s+/user:administrator",
    r"seDebugPrivilege\s+enabled"
]

PATH_TRAVERSAL_PATTERNS = [
    r"(\.\./|\.\.\\){2,}",
    r"/etc/passwd",
    r"c:\\boot\.ini",
    r"windows\\system32\\config"
]

class ThreatDetector:
    def __init__(self):
        self.ip_auth_failures = {} # Track failed logins by IP for brute force detection

    def analyze_log(self, log_source, log_level, message, raw_data=None):
        """
        Analyzes a log entry and returns a Security Event dictionary if a threat is detected, else None.
        """
        message_str = str(message)
        timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Extract IP if present
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", message_str)
        source_ip = ip_match.group(0) if ip_match else "192.168.1.100"

        # Extract User if present
        user_match = re.search(r"(?:user|account|username)[:=]\s*([a-zA-Z0-9_\-\.\\]+)", message_str, re.IGNORECASE)
        target_user = user_match.group(1) if user_match else "Unknown"

        # 1. Check SQL Injection
        for pattern in SQLI_PATTERNS:
            if re.search(pattern, message_str, re.IGNORECASE):
                return self._create_event(
                    severity="CRITICAL",
                    category="Web Application Attack",
                    title="SQL Injection (SQLi) Attempt Detected",
                    description=f"Potential SQL injection payload detected in input from IP {source_ip}.",
                    source_ip=source_ip,
                    target_user=target_user,
                    mitre="T1190 - Exploit Public-Facing Application",
                    matched_pattern=pattern,
                    raw_log=message_str
                )

        # 2. Check Cross-Site Scripting (XSS)
        for pattern in XSS_PATTERNS:
            if re.search(pattern, message_str, re.IGNORECASE):
                return self._create_event(
                    severity="HIGH",
                    category="Web Application Attack",
                    title="Cross-Site Scripting (XSS) Attack Detected",
                    description=f"Malicious script tags detected in request payload from {source_ip}.",
                    source_ip=source_ip,
                    target_user=target_user,
                    mitre="T1189 - Drive-by Compromise",
                    matched_pattern=pattern,
                    raw_log=message_str
                )

        # 3. Check Suspicious Execution / PowerShell Abuse
        for pattern in SUSPICIOUS_COMMAND_PATTERNS:
            if re.search(pattern, message_str, re.IGNORECASE):
                return self._create_event(
                    severity="HIGH" if "vssadmin" not in message_str else "CRITICAL",
                    category="Malicious Execution",
                    title="Suspicious Command / PowerShell Execution",
                    description=f"Anomalous execution flags detected: obfuscated command or administrative override.",
                    source_ip=source_ip,
                    target_user=target_user,
                    mitre="T1059.001 - PowerShell Execution",
                    matched_pattern=pattern,
                    raw_log=message_str
                )

        # 4. Privilege Escalation / User Creation
        for pattern in PRIVILEGE_ESCALATION_PATTERNS:
            if re.search(pattern, message_str, re.IGNORECASE):
                return self._create_event(
                    severity="CRITICAL",
                    category="Privilege Escalation",
                    title="Unauthorized Privilege Elevation / Account Creation",
                    description=f"Administrative event triggered or security group escalation attempted.",
                    source_ip=source_ip,
                    target_user=target_user,
                    mitre="T1078 - Valid Accounts / T1098 - Account Manipulation",
                    matched_pattern=pattern,
                    raw_log=message_str
                )

        # 5. Path Traversal
        for pattern in PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, message_str, re.IGNORECASE):
                return self._create_event(
                    severity="HIGH",
                    category="Directory Traversal",
                    title="Path Traversal / Unauthorized File Access",
                    description=f"Attempt to access restricted system directory files from IP {source_ip}.",
                    source_ip=source_ip,
                    target_user=target_user,
                    mitre="T1083 - File and Directory Discovery",
                    matched_pattern=pattern,
                    raw_log=message_str
                )

        # 6. Brute Force Authentication Detection
        if any(term in message_str.lower() for term in ["failed login", "authentication failure", "eventid: 4625", "invalid password"]):
            self.ip_auth_failures[source_ip] = self.ip_auth_failures.get(source_ip, 0) + 1
            if self.ip_auth_failures[source_ip] >= 3:
                fail_count = self.ip_auth_failures[source_ip]
                return self._create_event(
                    severity="CRITICAL" if fail_count > 5 else "HIGH",
                    category="Credential Access",
                    title="Brute Force Authentication Attack",
                    description=f"Multiple consecutive authentication failures ({fail_count} attempts) originating from {source_ip}.",
                    source_ip=source_ip,
                    target_user=target_user,
                    mitre="T1110 - Brute Force",
                    matched_pattern=f"{fail_count} failed auth attempts",
                    raw_log=message_str
                )
            else:
                return self._create_event(
                    severity="MEDIUM",
                    category="Authentication",
                    title="Failed Login Attempt",
                    description=f"Single authentication failure recorded for user '{target_user}' from {source_ip}.",
                    source_ip=source_ip,
                    target_user=target_user,
                    mitre="T1110.001 - Password Guessing",
                    matched_pattern="Failed login",
                    raw_log=message_str
                )

        # 7. Port Scan / Reconnaissance
        if any(term in message_str.lower() for term in ["port scan", "nmap", "syn flood", "connection refused flood"]):
            return self._create_event(
                severity="MEDIUM",
                category="Reconnaissance",
                title="Network Port Scan / Probe Detected",
                description=f"Sequential port probing activity detected from host {source_ip}.",
                source_ip=source_ip,
                target_user=target_user,
                mitre="T1046 - Network Service Discovery",
                matched_pattern="Port scan",
                raw_log=message_str
            )

        # Default: Low level warning if log level is ERROR or CRITICAL
        if log_level in ["ERROR", "CRITICAL", "FATAL"]:
            return self._create_event(
                severity="LOW",
                category="System Anomaly",
                title=f"System Log {log_level} Alert",
                description=message_str[:150],
                source_ip=source_ip,
                target_user=target_user,
                mitre="T1082 - System Information Discovery",
                matched_pattern=log_level,
                raw_log=message_str
            )

        return None

    def _create_event(self, severity, category, title, description, source_ip, target_user, mitre, matched_pattern, raw_log):
        event_uuid = f"EVT-{uuid.uuid4().hex[:8].upper()}"
        return {
            "event_id": event_uuid,
            "severity": severity,
            "category": category,
            "title": title,
            "description": description,
            "source_ip": source_ip,
            "target_user": target_user,
            "details": {
                "mitre_attack": mitre,
                "matched_pattern": matched_pattern,
                "raw_log_sample": raw_log[:300]
            }
        }
