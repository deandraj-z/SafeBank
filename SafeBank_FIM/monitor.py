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
    'file_count': 0,
    'last_update': None
}

# Configuration - Loaded from config.json
CONFIG = {
    'MONITOR_DIR': 'SafeBank_FIM',
    'BASELINE_FILE': 'baseline.json',
    'LOG_FILE': 'fim_monitor.log',
    'EMAIL_CONFIG': {
        'smtp_server': 'smtp.gmail.com',
        'smtp_port': 587,
        'sender_email': 'computetassignment@gmail.com',
        'sender_password': 'aklfrruakmzpawbk',
        'recipient_emails': ['computetassignment@gmail.com']
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
        subject = f"FIM Security Alert: {alert_type}"
        body = f"""
        SafeBank File Integrity Alert
        ----------------------------
        Type: {alert_type}
        File: {os.path.basename(file_path)}
        Path: {file_path}
        Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        Details: {details}
        
        Action Required: Investigate immediately.
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
            print(f"SECURITY ALERT: {subject} - {file_path} - {details}")
            return False

class FileChangeHandler(FileSystemEventHandler):
    def __init__(self, baseline, email_config, monitor_dir):
        super().__init__()
        self.baseline = baseline
        self.email_system = EmailAlertSystem(email_config)
        self.monitor_dir = monitor_dir
        self.logger = logging.getLogger('FIM_Handler')
        self._update_dashboard_data()
        
    def _update_dashboard_data(self):
        """Force update all dashboard metrics"""
        DASHBOARD_DATA['file_count'] = len(self.baseline['files'])
        DASHBOARD_DATA['last_scan'] = self.baseline.get('metadata', {}).get('created', 'Never')
        DASHBOARD_DATA['last_update'] = datetime.now().isoformat()

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
            self._update_dashboard_data()

    def on_created(self, event):
        if not event.is_directory:
            self._process_event(event.src_path, "CREATED")
            self._update_dashboard_data()

    def on_deleted(self, event):
        if not event.is_directory:
            self._process_event(event.src_path, "DELETED")
            self._update_dashboard_data()

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
            "MODIFIED": "Unauthorized content modification detected",
            "CREATED": "Unauthorized file added to system",
            "DELETED": "Critical file removed without authorization"
        }.get(alert_type.split()[-1], "Security-related change detected")
        
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
        if len(DASHBOARD_DATA['alerts']) > 50:
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
            logging.info(f"Loaded baseline with {len(baseline.get('files', {}))} files")
            return baseline
    except Exception as e:
        logging.error(f"Error loading baseline: {str(e)}")
        return {'metadata': {}, 'files': {}}

@app.route('/')
def dashboard():
    """Enhanced Flask dashboard with auto-refresh"""
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>SafeBank FIM Dashboard</title>
            <meta http-equiv="refresh" content="5">
            <style>
                body { 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    margin: 20px;
                    line-height: 1.6;
                }
                .alert { 
                    padding: 12px;
                    margin: 8px 0;
                    border-radius: 4px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                .modified { 
                    background-color: #fff8e1;
                    border-left: 5px solid #ffc107;
                }
                .created { 
                    background-color: #e3f2fd;
                    border-left: 5px solid #2196f3;
                }
                .deleted { 
                    background-color: #ffebee;
                    border-left: 5px solid #f44336;
                }
                .stats { 
                    background-color: #f5f5f5;
                    padding: 20px;
                    margin-bottom: 25px;
                    border-radius: 5px;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                }
                h1 { 
                    color: #2c3e50;
                    border-bottom: 2px solid #eee;
                    padding-bottom: 10px;
                }
                .timestamp {
                    color: #7f8c8d;
                    font-size: 0.9em;
                    text-align: right;
                }
            </style>
        </head>
        <body>
            <h1>SafeBank File Integrity Monitor</h1>
            <div class="timestamp">Last updated: {{ data.last_update }}</div>
            
            <div class="stats">
                <h3>System Status</h3>
                <p><strong>Files monitored:</strong> {{ data.file_count }}</p>
                <p><strong>Last baseline scan:</strong> {{ data.last_scan }}</p>
                <p><strong>Security alerts:</strong> {{ data.alerts|length }}</p>
            </div>
            
            <h2>Recent Security Events</h2>
            {% for alert in data.alerts|reverse %}
            <div class="alert {{ alert.type.lower().split()[-1] }}">
                <strong>[{{ alert.time }}] {{ alert.type }}</strong><br>
                <strong>File:</strong> {{ alert.file }}<br>
                <strong>Location:</strong> {{ alert.path }}<br>
                <strong>Severity:</strong> {{ alert.details }}
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

