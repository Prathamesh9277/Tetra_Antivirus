import tkinter as tk
from tkinter import messagebox
import psutil
#Function to get RAM usage
def get_ram_usage():
    memory_info = psutil.virtual_memory()
    percent = memory_info.percent
    if percent > 80:
        messagebox.showinfo("memoery usage is to high")
        high_memory_process = get_high_memory_process()
        if high_memory_process:
           terminate_high_memory_process(get_high_memory_process)

    return percent

def get_high_memory_process():
    # Collect high memory processes
    processes = [(proc.pid, proc.info['name'], proc.info['memory_percent'])
                 for proc in psutil.process_iter(['name', 'memory_percent'])
                 if proc.info['memory_percent'] > 3]
    
    # Sort the processes by memory usage in descending order
    processes.sort(key=lambda x: x[2], reverse=True)
    
    # Create a string representation of the process information
    processes_info = "\n".join([f"PID: {proc[0]}, Name: {proc[1]}, Memory: {proc[2]:.2f}%" for proc in processes])
    
    return processes_info

def terminate_high_memory_process(processes_info):
    processes_info, processes = get_high_memory_process()
    
    if processes:  # Check if there are any high memory processes
        highest_memory_process = processes[0]  # Get the process with the highest memory usage
        pid_to_terminate = highest_memory_process[0]  # Extract the PID
        
        response = messagebox.askyesno("Terminate Process", f"The following process is consuming a lot of memory:\n{processes_info}\n\nDo you want to terminate it?")
        
        if response:
            try:
                p = psutil.Process(pid_to_terminate)
                p.terminate()  # Terminate the process
                messagebox.showinfo("Process Terminated", f"Process with PID {pid_to_terminate} has been terminated.")
            except Exception as e:
                messagebox.showinfo("Error", f"Failed to terminate process: {e}")
    else:
        messagebox.showinfo("No High Memory Processes", "No processes are consuming high memory.")
        
# Update the animate function to include the ax parameter
def animate(i, x_data, y_data, line, ax):
    ram_usage = get_ram_usage()
    x_data.append(i)  # Time steps
    y_data.append(ram_usage)  # RAM usage

    # Limit the lists to 20 items for smoother graph updates
    x_data = x_data[-20:]
    y_data = y_data[-20:]

    line.set_data(x_data, y_data)
    
    # Update the limits of the graph to fit new data
    ax.set_xlim(max(0, i-20), i+1)
    ax.set_ylim(0, 100)  # RAM usage is percentage, so range is 0-100

    return line,