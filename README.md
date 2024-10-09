Project Description
Tetra Antivirus is a lightweight antivirus application built for Linux systems. It performs file and directory scans, detects malware through heuristic and signature-based analysis,
monitors system performance,and offers network security features like suspicious port monitoring and packet filtering.
The tool is built with a focus on ease of use, speed, and security, providing essential malware detection and removal functionalities.

Features
File and Directory Scanning: Detects malware in files and directories using both heuristic (extension and size-based) and signature-based (SHA-256 hashing) methods.
Junk File Removal: Scans and removes junk files from system directories like /tmp.
RAM Usage Monitoring: Continuously monitors RAM usage and provides a visual graph. Automatically detects and stops high RAM-consuming processes.
Network Security: Monitors open ports, detects suspicious services, and captures packets from suspicious ports. Filters based on blacklisted IPs and excessive login attempts.
Multithreading: Ensures background processes like packet capturing and malware scanning run in parallel without freezing the user interface.

Available Features:
File/Directory Scan: Choose a file or directory to scan for malware.
Junk File Removal: Identify and clean temporary system files.
RAM Monitoring: View real-time RAM usage and manage memory-consuming processes.
Network Monitoring: Capture suspicious packets and analyze active ports.

Technologies Used
Python: Core programming language.
Tkinter: For creating the graphical user interface (GUI).
Scapy: For packet capture and network monitoring.
psutil: For system and process monitoring.
matplotlib: For visualizing system metrics like RAM usage.
threading: For implementing multithreaded operations.

IMP----------------------

Tetra Antivirus is designed primarily for Linux-based systems. One of the key features of the application is that it does not require running with root permissions by default. 
The application will prompt for root permissions only when needed, such as when performing actions like removing junk files or terminating high RAM-consuming processes. 
This ensures minimal disruption to regular user activities while maintaining system security.

