import os
import hashlib
import json
import argparse
from datetime import datetime
from pathlib import Path

def calculate_file_hash(file_path):
    """Calculate SHA-256 hash of a file"""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(65536)  # Read in 64kb chunks
                if not data:
                    break
                sha256.update(data)
        return sha256.hexdigest()
    except Exception as e:
        print(f"Error calculating hash for {file_path}: {str(e)}")
        return None

def create_baseline(directory, output_file='baseline.json'):
    """Create baseline of all files in directory and subdirectories"""
    baseline = {
        'metadata': {
            'created': datetime.now().isoformat(),
            'directory': os.path.abspath(directory),
            'total_files': 0
        },
        'files': {}
    }

    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            relative_path = os.path.relpath(file_path, directory)
            
            try:
                file_hash = calculate_file_hash(file_path)
                if file_hash is None:
                    continue
                    
                file_stats = os.stat(file_path)
                
                baseline['files'][relative_path] = {
                    'hash': file_hash,
                    'size': file_stats.st_size,
                    'last_modified': file_stats.st_mtime,
                    'permissions': oct(file_stats.st_mode)[-4:]
                }
                baseline['metadata']['total_files'] += 1
            except Exception as e:
                print(f"Error processing {file_path}: {str(e)}")

    # Save baseline to file
    with open(output_file, 'w') as f:
        json.dump(baseline, f, indent=2)
    
    print(f"Baseline created successfully with {baseline['metadata']['total_files']} files.")
    return baseline

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Create baseline for FIM system')
    parser.add_argument('--dir', type=str, default='SafeBank_Data',
                       help='Directory to monitor (default: SafeBank_Data)')
    parser.add_argument('--output', type=str, default='baseline.json',
                       help='Output baseline file (default: baseline.json)')
    args = parser.parse_args()

    if not os.path.exists(args.dir):
        print(f"Error: Directory {args.dir} does not exist")
        exit(1)

    create_baseline(args.dir, args.output)