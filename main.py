import hashlib
import os
import time
import argparse
from datetime import datetime

#Default Configuration
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "file_changes.log")
INTERVAL = 30  # 30 seconds between file integrity checks.

def file_to_hash(file_path):
    """Calculate SHA-256 hash of a file."""
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return None

    try:
        hash_obj = hashlib.sha256() # Convert to a SHA-256 hash object
        with open(file_path, 'rb') as f:
            while True:
                    chunk = f.read(4096)  # Read 4KB chunks at a time
                    if not chunk:
                        break
                    hash_obj.update(chunk)# Add file data to the hash
        return hash_obj.hexdigest()

    except Exception as e:
        print(f"Error calculating hash for {file_path}: {e}")
        return None

def monitor_files(files_to_monitor, interval):
    """Monitor changes to given files over an interval of time"""

    # DICTIONARIES TO STORE FILE INFO
    file_hashes = {}
    file_sizes = {}

    print(f"Monitoring: {files_to_monitor}")
    print(f"Logging changes to: {LOG_FILE}")
    print(f"Check interval: {interval} seconds")
    print("Press Ctrl+C to stop.\n")


    try:
        while True:
            for file_path in files_to_monitor:
                if not os.path.exists(file_path):
                    print(f"File not found: {file_path}")
                    continue

                current_size = os.path.getsize(file_path)

                if file_path in file_sizes and file_sizes[file_path] == current_size:
                    continue


                current_hash = file_to_hash(file_path)

                if current_hash is None:
                    continue

                if file_path not in file_hashes:
                    #store file info if not already in dictionary
                    file_hashes[file_path] = current_hash
                    file_sizes[file_path] = current_size
                    print(f"Initial hash for {file_path}: {current_hash}")

                elif file_hashes[file_path] != current_hash:
                    #recalculate file hash after changes occur if not already in dictionary
                    print(f"Change detected in {file_path}!")
                    log_change(file_path, file_hashes[file_path], current_hash)
                    file_hashes[file_path] = current_hash
                    file_sizes[file_path] = current_size

            time.sleep(INTERVAL)

    except KeyboardInterrupt:
        print("\nMonitoring stopped.")

def log_change(file_path, old_hash, new_hash):
        try:
            if not os.path.exists(LOG_DIR):
                os.makedirs(LOG_DIR)

            log_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"[{log_time}] CHANGE: {file_path}\nOld Hash: {old_hash}\nNew Hash: {new_hash}\n"

            if file_path.lower().endswith(('.exe', '.dll')):
                log_entry += "SECURITY NOTE: Executable/Driver file modified\n"
                print(f"SECURITY: {os.path.basename(file_path)} is an executable!") # special messages as if dll or exe file changes malware might be present

            with open(LOG_FILE, "a") as log:
                log.write(log_entry)

            print(log_entry)

        except Exception as e:
            print(f"Error logging change: {e}")


if __name__ == "__main__":
    # Set up command-line arguments
    parser = argparse.ArgumentParser(description="File Integrity Monitor (FIM)")
    parser.add_argument("files", nargs="+")
    parser.add_argument("--interval", type=int, default=INTERVAL)
    args = parser.parse_args()

    # Start monitoring
    monitor_files(args.files, args.interval)


