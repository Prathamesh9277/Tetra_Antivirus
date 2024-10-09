import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk  # For using the progress bar
import os
import threading
import subprocess
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.animation as animation
from Tetra_simple_func import signature_analysis ,heuristic_analysis , user_permission , request_root_permission , Multi_scan
from health_checker import animate , get_ram_usage ,get_high_memory_process , terminate_high_memory_process
from port_scan_detail import main

stop_scan_button = False
# Function to scan a selected file
def stop_scan():
    global stop_scan_button
    stop_scan_button = True
    progress_bar['value'] = 0 
    messagebox.showinfo("Stopped","scan stopped")

def scan_file():
    file_path = filedialog.askopenfilename(title="Select a File")  # Open file dialog to select file
    if file_path:
        result1 , result2 = Multi_scan(file_path)
        combined_message = f"Signature Scan Result: {result1}\nHeuristic Scan Result: {result2}"
        messagebox.showinfo("Scan Results", combined_message)

# Function to scan all files in a directory
def scan_directory():
    global stop_scan_button
    stop_scan_button = False
    directory = filedialog.askdirectory(title="Select a Directory")  # Open directory dialog to select folder
    if directory:
        threading.Thread(target=run_directory_scan, args=(directory,)).start()

def run_directory_scan(directory):
    total_files = sum([len(files) for _, _, files in os.walk(directory)])  # Total number of files
    progress_bar['maximum'] = total_files  # Set the maximum value of the progress bar
    progress_bar['value'] = 0  # Reset progress bar
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            print(f"Scanning {file_path}...")  # Optional: show scanning progress in console
            if stop_scan_button:
                return "stopped"
            result1 , result2 = Multi_scan(file_path)
                
            # Update the progress bar
            progress_bar['value'] += 1
            # Debug: show current progress
            root_window.update_idletasks()  # Update the GUI to reflect the progress

            if "suspicious" in result1 or "suspicious" in result2:
                user_permission(file_path)
                

def junk_clear():
    file_paths = ["/tmp" , "/var/tmp" , "/var/log" , "/var/cache"]
    for file_path in file_paths:
        try:
            if os.path.exists(file_path) and os.listdir(file_path):
                for file_name in os.listdir(file_path):
                    full_path = os.path.join(file_path , file_name)
                    if os.path.isfile(full_path):
                        user_permission(full_path)
                print(f"Junk files are removed in {file_path}")
            else:
                print("No files found in file path")
        except Exception as e:
            print(f"Error: {e}")

def update_process_info():
    processes_info = get_high_memory_process()
    process_text.delete(1.0,tk.END)
    process_text.insert(tk.END , processes_info)

    process_text.after('1000',update_process_info)

def update_display():
    global secure_ports, suspicious_ports1
    # Clear the Text widget before displaying new results
    port_display_text.delete(1.0, tk.END)

    # Display secure ports
    port_display_text.insert(tk.END, "Secure Ports:\n")
    for port, service, process in secure_ports:
        port_display_text.insert(tk.END, f"Port: {port}, Service: {service}, Process: {process}\n")

    # Display suspicious ports
    port_display_text.insert(tk.END, "\nSuspicious Ports:\n")
    for port, service, process in suspicious_ports1:
        port_display_text.insert(tk.END, f"Port: {port}, Service: {service}, Process: {process}\n")

def start_monitoring_display():
    while True:
        main()  # Update secure_ports and suspicious_ports
        update_display()  # Update the GUI with new port information
        time.sleep(5)  # Sleep for a while before the next check

# Main GUI window setup
root_window = tk.Tk()
root_window.title("Malware Scanner")
root_window.geometry("1000x800")
root_window.configure(bg="#e0e0e0")  # Light gray background for a cleaner look

# Create a frame for layout
layout_frame = tk.Frame(root_window, bg="#e0e0e0")
layout_frame.pack(fill="both", expand=True)

# Create a left frame for buttons
left_frame = tk.Frame(layout_frame, bg="#e0e0e0")
left_frame.grid(row=0, column=0, padx=20, pady=20, sticky="n")

# Add a title label
title_label = tk.Label(left_frame, text="Malware Scanner", font=("Helvetica", 20, "bold"), bg="#e0e0e0", fg="#333333")
title_label.pack(pady=20)

# Add instruction label
instruction_label = tk.Label(left_frame, text="Select an option to scan:", font=("Helvetica", 14), bg="#e0e0e0", fg="#555555")
instruction_label.pack(pady=10)

# Create buttons in a vertical layout
scan_file_button = tk.Button(left_frame, text="Scan a File", command=scan_file, 
                             font=("Helvetica", 12), bg="#4CAF50", fg="white", width=20, height=2)
scan_file_button.pack(pady=10)

scan_dir_button = tk.Button(left_frame, text="Scan a Directory", command=scan_directory, 
                            font=("Helvetica", 12), bg="#2196F3", fg="white", width=20, height=2)
scan_dir_button.pack(pady=10)

junk_clear_button = tk.Button(left_frame, text="Remove Junk Files", command=junk_clear, 
                              font=("Helvetica", 12), bg="#FF9800", fg="white", width=20, height=2)
junk_clear_button.pack(pady=10)

# Add a stop scan button at the bottom
stop_button = tk.Button(left_frame, text="Stop Scan", command=stop_scan, 
                        font=("Helvetica", 12), bg="#f44336", fg="white", width=20, height=2)
stop_button.pack(pady=10)

# Add a progress bar inside the left frame (under the buttons)
progress_label = tk.Label(left_frame, text="Progress:", font=("Helvetica", 12), bg="#e0e0e0", fg="#555555")
progress_label.pack(pady=5)
progress_bar = ttk.Progressbar(left_frame, orient="horizontal", mode="determinate", length=250)
progress_bar.pack(pady=10)

# Create a right frame for the RAM graph
right_frame = tk.Frame(layout_frame, bg="#e0e0e0")
right_frame.grid(row=0, column=1, padx=20, pady=20, sticky="n")

# Create a frame for displaying high memory processes
process_frame = tk.Frame(layout_frame, bg="#e0e0e0")
process_frame.grid(row=1, column=0, padx=20, pady=20, sticky="nsew")

process_label = tk.Label(process_frame, text="High Memory Processes", font=("Helvetica", 16, "bold"), bg="#e0e0e0", fg="#333333")
process_label.pack(pady=10)

# Create a Text widget to show the high memory processes
process_text = tk.Text(process_frame, height=10, width=50, font=("Helvetica", 12), bg="#ffffff", fg="#000000")
process_text.pack(pady=10)

# Displaying ports side by side
port_display_frame = tk.Frame(layout_frame, bg="#e0e0e0")
port_display_frame.grid(row=1, column=1, padx=20, pady=20, sticky="nsew")

port_display_label = tk.Label(port_display_frame, text="Port Status", font=("Helvetica", 16, "bold"), bg="#e0e0e0", fg="#333333")
port_display_label.pack(pady=10)

port_display_text = tk.Text(port_display_frame, height=10, width=50, font=("Helvetica", 12), bg="#ffffff", fg="#000000")
port_display_text.pack(pady=10)

# Adjust grid weights to ensure frames resize properly
layout_frame.grid_rowconfigure(1, weight=1)
layout_frame.grid_columnconfigure(0, weight=1)
layout_frame.grid_columnconfigure(1, weight=1)

# Set up the graph using matplotlib
fig, ax = plt.subplots()
ax.set_title("RAM Usage Over Time")
ax.set_xlabel("Time (s)")
ax.set_ylabel("RAM Usage (%)")
x_data, y_data = [], []
line, = ax.plot([], [], color="blue")

# Create a canvas for the graph and add it to the right frame
canvas = FigureCanvasTkAgg(fig, master=right_frame)
canvas.get_tk_widget().pack(fill="both", expand=True)

# Animate the graph with matplotlib animation
ani = animation.FuncAnimation(fig, animate, fargs=(x_data, y_data, line, ax), interval=1000)

if __name__ == "__main__":
    monitoring_thread = threading.Thread(target=start_monitoring_display)
    monitoring_thread.daemon = True  # Daemonize thread to exit when the main program exits
    monitoring_thread.start()

update_process_info()
# Run the GUI loop
root_window.mainloop()
