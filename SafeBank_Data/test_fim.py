import os
import time
import random
import string
import json
import argparse
from pathlib import Path

# Configuration - loaded from config.json
CONFIG = {
    'MONITOR_DIR': 'SafeBank_Data',
    'TEST_FILES': {
        "Financial_Transactions/transactions_2025_01.csv": "Original transaction data",
        "Personal_Information/customers_db.csv": "Customer records",
        "Internal_Configurations/db_config.ini": "[database]\nhost=localhost"
    }
}

def load_config():
    try:
        with open('config.json') as f:
            return json.load(f)
    except FileNotFoundError:
        print("config.json not found, using defaults")
        return CONFIG
    except Exception as e:
        print(f"Error loading config: {str(e)}")
        return CONFIG

CONFIG = load_config()

def setup_test_environment():
    """Create test files if they don't exist"""
    for rel_path, content in CONFIG['TEST_FILES'].items():
        path = Path(CONFIG['MONITOR_DIR']) / rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text(content)
            print(f"Created test file: {rel_path}")

def simulate_attacks():
    """Execute test scenarios"""
    print("\n=== Starting FIM System Tests ===")
    
    # 1. Modify existing file
    target = Path(CONFIG['MONITOR_DIR']) / "Financial_Transactions/transactions_2025_01.csv"
    original_content = target.read_text()
    new_content = original_content + "\n9999,HACKER_ACCOUNT,1000000.00,Unauthorized Transfer"
    target.write_text(new_content)
    print(f"\n[TEST 1] Modified file: {target}")
    print("Expected: System should detect hash mismatch and send alert")
    time.sleep(2)  # Allow detection
    
    # 2. Add unauthorized file
    malware_path = Path(CONFIG['MONITOR_DIR']) / "malware.exe"
    malware_path.write_text("".join(random.choices(string.ascii_letters, k=1000)))
    print(f"\n[TEST 2] Added unauthorized file: malware.exe")
    print("Expected: System should detect new file and send alert")
    time.sleep(2)
    
    # 3. Delete critical file
    critical_file = Path(CONFIG['MONITOR_DIR']) / "Internal_Configurations/db_config.ini"
    critical_file.unlink()
    print(f"\n[TEST 3] Deleted critical file: {critical_file.name}")
    print("Expected: System should detect deletion and send alert")
    time.sleep(2)
    
    # Restore original state (optional)
    target.write_text(original_content)
    malware_path.unlink(missing_ok=True)
    # Note: Won't restore deleted file - lets you verify detection

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Test FIM System')
    parser.add_argument('--config', type=str, default='config.json',
                       help='Configuration file (default: config.json)')
    args = parser.parse_args()
    
    try:
        with open(args.config) as f:
            CONFIG.update(json.load(f))
    except FileNotFoundError:
        print(f"Config file {args.config} not found, using defaults")
    except Exception as e:
        print(f"Error loading config: {str(e)}")
    
    setup_test_environment()
    simulate_attacks()
    print("\n=== Tests completed. Check logs and emails ===")

