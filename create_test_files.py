import os
from pathlib import Path

# Configuration - creates SafeBank_Data/SafeBank_Data structure
BASE_DIR = "SafeBank_Data"
MONITOR_DIR = os.path.join(BASE_DIR, "SafeBank_Data")
TEST_FILES = {
    "Financial_Transactions/transactions_2025_01.csv": (
        "ID,Account,Amount,Description\n"
        "1001,ACCT_001,1500.00,Salary Deposit\n"
        "1002,ACCT_002,200.00,Transfer"
    ),
    "Personal_Information/customers_db.csv": (
        "CustomerID,Name,Email\n"
        "001,John Doe,john@example.com\n"
        "002,Jane Smith,jane@example.com"
    ),
    "Internal_Configurations/db_config.ini": (
        "[database]\n"
        "host=localhost\n"
        "port=3306\n"
        "username=admin\n"
        "password=s3cureP@ss"
    ),
    "Internal_Configurations/app_settings.json": (
        '{"debug": false, "timeout": 30}'
    )
}

def create_test_environment():
    """Create the nested test directory structure and files"""
    try:
        # Create both directory levels
        Path(MONITOR_DIR).mkdir(parents=True, exist_ok=True)
        
        # Create files with content
        for rel_path, content in TEST_FILES.items():
            # Convert path to OS-specific format
            rel_path = rel_path.replace('/', os.sep)
            file_path = Path(MONITOR_DIR) / rel_path
            
            # Ensure parent directories exist
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write file content
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            print(f"Created: {file_path}")

        # Create empty directories that might be needed
        (Path(MONITOR_DIR) / "Audit_Logs").mkdir(exist_ok=True)
        (Path(MONITOR_DIR) / "Backups").mkdir(exist_ok=True)

        print("\nTest environment created successfully!")
        print(f"Root directory: {Path(BASE_DIR).resolve()}")
        print(f"Monitored directory: {Path(MONITOR_DIR).resolve()}")
        print(f"Total files created: {len(TEST_FILES)}")
    
    except Exception as e:
        print(f"\nError creating test environment: {str(e)}")
        print("Please check permissions and disk space.")

if __name__ == "__main__":
    print("Creating SafeBank test environment...")
    create_test_environment()
    print("\nNext steps:")
    print("1. Run: python create_baseline.py")
    print("2. Run: python monitor_files.py")

