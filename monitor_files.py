import os
import json
import hashlib
import time
import logging
import smtplib
import argparse
from pathlib import Path
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from flask import Flask, render_template_string

# Flask dashboard setup
app = Flask(__name__)
DASHBOARD_DATA = {
    'alerts': [],
    'last_scan': None,
    'file_count': 0
}

# Configuration - Now loaded from config.json
CONFIG = {
    'MONITOR_DIR': 'SafeBank_Data',
    'BASELINE_FILE': 'baseline.json',
    'LOG_FILE': 'fim_monitor.log',
    'EMAIL_CONFIG': {
        'smtp_server': 'smtp.gmail.com',
        'smtp_port': 587,
        'sender_email': 'your_email@gmail.com',
        'sender_password': '',  # Should be set in config.json
        'recipient_emails': ['admin@yourdomain.com']
    },
    'DASHBOARD_PORT': 5000
}

def load_config():
    """Load configuration from file or environment variables"""
    try:
        with open('config.json') as f:
            return json.load(f)
    except FileNotFoundError:
        logging.warning("config.json not found, using defaults")
        return CONFIG
    except Exception as e:
        logging.error(f"Error loading config: {str(e)}")
        return CONFIG

CONFIG = load_config()

class EmailAlertSystem:
    """Handles email notifications for file changes"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger('FIM_EmailAlerts')
        
    def send_alert(self, alert_type, file_path, details=""):
        """Send email notification for detected changes"""
        subject = f"FIM Alert: {alert_type}"
        body = f"""
        SafeBank File Integrity Alert
        ----------------------------
        Type: {alert_type}
        File: {os.path.basename(file_path)}
        Path: {file_path}
        Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        Details: {details}
        
        This requires immediate investigation.
        """
        
        try:
            msg = MIMEMultipart()
            msg['From'] = self.config['sender_email']
            msg['To'] = ", ".join(self.config['recipient_emails'])
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))
            
            with smtplib.SMTP(
                self.config['smtp_server'],
                self.config['smtp_port']
            ) as server:
                server.starttls()
                server.login(
                    self.config['sender_email'],
                    self.config['sender_password']
                )
                server.send_message(msg)
            
            self.logger.info(f"Email alert sent: {subject}")
            return True
        except Exception as e:
            self.logger.error(f"Email failed: {str(e)}")
            print(f"ALERT: {subject} - {file_path} - {details}")
            return False

class FileChangeHandler(FileSystemEventHandler):
    def __init__(self, baseline, email_config, monitor_dir):
        super().__init__()
        self.baseline = baseline
        self.email_system = EmailAlertSystem(email_config)
        self.monitor_dir = monitor_dir
        self.logger = logging.getLogger('FIM_Handler')
        
    def calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file"""
        sha256 = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                while True:
                    data = f.read(65536)  # 64KB chunks
                    if not data:
                        break
                    sha256.update(data)
            return sha256.hexdigest()
        except Exception as e:
            self.logger.error(f"Hash calculation failed: {str(e)}")
            return None

    def on_modified(self, event):
        if not event.is_directory:
            self._process_event(event.src_path, "MODIFIED")

    def on_created(self, event):
        if not event.is_directory:
            self._process_event(event.src_path, "CREATED")

    def on_deleted(self, event):
        if not event.is_directory:
            self._process_event(event.src_path, "DELETED")

    def _process_event(self, file_path, change_type):
        try:
            relative_path = os.path.relpath(file_path, self.monitor_dir)
            
            if change_type == "MODIFIED":
                current_hash = self.calculate_file_hash(file_path)
                if current_hash and relative_path in self.baseline['files']:
                    if current_hash != self.baseline['files'][relative_path]['hash']:
                        self._trigger_alert("File Modified", file_path)

            elif change_type == "CREATED":
                if relative_path not in self.baseline['files']:
                    self._trigger_alert("New File Detected", file_path)

            elif change_type == "DELETED":
                if relative_path in self.baseline['files']:
                    self._trigger_alert("File Deleted", file_path)

        except Exception as e:
            self.logger.error(f"Error processing event: {str(e)}")

    def _trigger_alert(self, alert_type, file_path):
        details = {
            "MODIFIED": "File content changed",
            "CREATED": "New file appeared",
            "DELETED": "Critical file removed"
        }.get(alert_type.split()[-1], "Unknown change")
        
        self.logger.warning(f"{alert_type}: {file_path}")
        self.email_system.send_alert(alert_type, file_path, details)
        
        # Update dashboard data
        DASHBOARD_DATA['alerts'].append({
            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'type': alert_type,
            'file': os.path.basename(file_path),
            'path': file_path,
            'details': details
        })
        if len(DASHBOARD_DATA['alerts']) > 50:  # Keep last 50 alerts
            DASHBOARD_DATA['alerts'] = DASHBOARD_DATA['alerts'][-50:]

def initialize_environment():
    """Ensure required directories and files exist"""
    os.makedirs(CONFIG['MONITOR_DIR'], exist_ok=True)
    
    if not os.path.exists(CONFIG['BASELINE_FILE']):
        with open(CONFIG['BASELINE_FILE'], 'w') as f:
            json.dump({'metadata': {}, 'files': {}}, f)
        logging.info(f"Created baseline file: {CONFIG['BASELINE_FILE']}")

def load_baseline():
    """Load the baseline hashes from file"""
    try:
        with open(CONFIG['BASELINE_FILE'], 'r') as f:
            baseline = json.load(f)
            DASHBOARD_DATA['file_count'] = baseline.get('metadata', {}).get('total_files', 0)
            DASHBOARD_DATA['last_scan'] = baseline.get('metadata', {}).get('created', 'Never')
            return baseline
    except Exception as e:
        logging.error(f"Error loading baseline: {str(e)}")
        return {'metadata': {}, 'files': {}}

@app.route('/')
def dashboard():
    """Simple Flask dashboard"""
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>SafeBank FIM Dashboard</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .alert { padding: 10px; margin: 5px 0; border-radius: 4px; }
                .modified { background-color: #fff3cd; border-left: 5px solid #ffc107; }
                .created { background-color: #d4edda; border-left: 5px solid #28a745; }
                .deleted { background-color: #f8d7da; border-left: 5px solid #dc3545; }
                .stats { background-color: #e2e3e5; padding: 15px; margin-bottom: 20px; }
            </style>
        </head>
        <body>
            <h1>SafeBank File Integrity Monitor</h1>
            <div class="stats">
                <h3>System Status</h3>
                <p>Files monitored: {{ data.file_count }}</p>
                <p>Last baseline scan: {{ data.last_scan }}</p>
                <p>Alerts detected: {{ data.alerts|length }}</p>
            </div>
            
            <h2>Recent Alerts</h2>
            {% for alert in data.alerts|reverse %}
            <div class="alert {{ alert.type.lower().split()[-1] }}">
                <strong>[{{ alert.time }}] {{ alert.type }}</strong><br>
                File: {{ alert.file }}<br>
                Path: {{ alert.path }}<br>
                Details: {{ alert.details }}
            </div>
            {% endfor %}
        </body>
        </html>
    ''', data=DASHBOARD_DATA)

def start_monitoring():
    """Start the file integrity monitoring"""
    initialize_environment()
    baseline = load_baseline()
    
    event_handler = FileChangeHandler(baseline, CONFIG['EMAIL_CONFIG'], CONFIG['MONITOR_DIR'])
    observer = Observer()
    
    try:
        observer.schedule(event_handler, CONFIG['MONITOR_DIR'], recursive=True)
        observer.start()
        logging.info(f"Monitoring started on {CONFIG['MONITOR_DIR']}")
        
        # Start Flask dashboard in a separate thread
        from threading import Thread
        flask_thread = Thread(target=lambda: app.run(
            host='0.0.0.0', 
            port=CONFIG.get('DASHBOARD_PORT', 5000),
            debug=False,
            use_reloader=False
        ))
        flask_thread.daemon = True
        flask_thread.start()
        logging.info(f"Dashboard started on http://localhost:{CONFIG.get('DASHBOARD_PORT', 5000)}")
        
        # Verify email connectivity
        if event_handler.email_system.send_alert(
            "FIM System Startup", 
            CONFIG['MONITOR_DIR'],
            "Monitoring system initialized successfully"
        ):
            logging.info("Email test successful")
        
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        logging.info("Monitoring stopped by user")
    except Exception as e:
        logging.error(f"Monitoring failed: {str(e)}")
    finally:
        observer.join()

if __name__ == "__main__":
    # Configure dual logging (file + console)
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(CONFIG['LOG_FILE']),
            logging.StreamHandler()
        ]
    )
    
    parser = argparse.ArgumentParser(description='SafeBank FIM System')
    parser.add_argument('--config', type=str, default='config.json',
                       help='Configuration file (default: config.json)')
    args = parser.parse_args()
    
    try:
        with open(args.config) as f:
            CONFIG.update(json.load(f))
    except FileNotFoundError:
        logging.warning(f"Config file {args.config} not found, using defaults")
    except Exception as e:
        logging.error(f"Error loading config: {str(e)}")
    
    logging.info("Starting SafeBank FIM System")
    start_monitoring()