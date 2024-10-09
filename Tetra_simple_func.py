import hashlib
import os
import subprocess
from tkinter import messagebox  
import threading

def Multi_scan(file_path):

    if file_path:
        result1 = result2 = None
        def run_signature_analysis():
            nonlocal result1
            result1 = signature_analysis(file_path) 

        def run_heuristic_analysis():
            nonlocal result2
            result2 = heuristic_analysis(file_path)


        thread1 = threading.Thread(target=run_signature_analysis)
        thread2 = threading.Thread(target=run_heuristic_analysis)

        thread1.start()
        thread2.start()
        thread1.join()
        thread2.join()

        return result1 , result2

def user_permission(file_path):
    user_response = messagebox.askyesno("Malware Detected", f"Suspicious file detected: {file_path}\nDo you want to delete it?")
    if user_response:    
        try:
            os.remove(file_path)
            print("File has been successfully deleted from the system")
        except PermissionError:
            print(f"Permission denied: Cannot delete {file_path}. Requesting root access.")
            request_root_permission

suspicious_extensions = [ '.exe', '.bat', '.scr', '.vbs', '.dll', '.pif', '.cmd', '.com', '.msi',
    '.js', '.jse', '.ps1', '.sh', '.apk', '.jar']

def user_permission(file_path):
    user_response = messagebox.askyesno("Malware Detected", f"Suspicious file detected: {file_path}\nDo you want to delete it?")
    if user_response:    
        try:
            os.remove(file_path)
            print("file has been successfully deleted from the system")
        except PermissionError:
            print(f"Permission denied: Cannot delete {file_path}. Requesting root access.")
            request_root_permission(file_path)
        except Exception as e:
            print(f"Error: Cannot delete the file {file_path}:{e}")


def request_root_permission(file_path):
    try:
        subprocess.run(["sudo","rm",file_path], check=True)
        print("Suspecious file is successfully detelted form the system")
    except Exception as e:
        print(f"Error: Could not delete {file_path} with root access: {e}")

# Function to generate SHA-256 hash of a file
def sha256_hash(filename):
    try:
        with open(filename, "rb") as f:
            file_data = f.read()  # Read file as bytes
            sha256hash = hashlib.sha256(file_data).hexdigest()  # Compute SHA-256 hash
        return sha256hash
    except Exception as e:
        print(f"Error reading {filename}: {e}")
        return None

# Function to check if the file is malware by comparing the hash with known malware hashes
def signature_analysis(file_path):

    # Get the SHA-256 hash of the file
    file_hash = sha256_hash(file_path)
    
    if file_hash is None:
        return "Error: Could not compute hash for this file."

    # Dictionary to store malware hash and its name
    known_hashes = {}

    try:
        # Read the malware hashes from the virus_hashes.txt file
        with open("VirusDataBaseHash.bav", "r") as malware_hashes:
            for line in malware_hashes:
                # Split the line into hash and malware name
                hash_value, malware_name = line.strip().split(":")
                known_hashes[hash_value] = malware_name
    except Exception as e:
        return f"Error: Unable to read the malware hash database. {e}"

    # Check if the file hash is in known hashes
    if file_hash in known_hashes:
        return f"suspicious! Malware Detected: {known_hashes[file_hash]}\nCheck details on VirusTotal: https://www.virustotal.com/gui/search/{file_hash}"
    else:
        return "Safe! No malware found."

def heuristic_analysis(file_path):
    #get the file extension
    _, file_extension = os.path.splitext(file_path)
    if file_extension.lower() in suspicious_extensions:
        print(f"Suspecious file detected based on extension")
        file_size = os.path.getsize(file_path)

        if file_size == 0:
            print("file is empty (potentially malicious)")
            user_permission(file_path)

        if file_extension == ".exe" and file_size <100000:
            print("suspicious : small executable file detected")
            user_permission(file_path)

    return "file seems clean"