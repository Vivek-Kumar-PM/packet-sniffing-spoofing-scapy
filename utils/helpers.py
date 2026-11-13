# ============================================================
# FILE: utils/helpers.py
# PURPOSE: Shared utility functions used across all files
# WHY NEEDED: Instead of writing timestamp and print formatting
#             code in every file, we write it once here and
#             import it anywhere. This is called DRY principle
#             (Don't Repeat Yourself) in software engineering.
# ============================================================

from datetime import datetime  
# datetime module gives us access to current date and time
# We use this to timestamp every packet log entry

def get_timestamp():
    # Returns current time formatted as: 2024-01-15 14:30:25
    # Used to record EXACTLY when each packet was captured or sent
    # Important for security logs and forensic analysis
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def print_separator():
    # Prints a visual divider line between packet outputs
    # Makes terminal output easier to read when many packets appear
    # Without this, all packet info would blend together
    print("=" * 60)

def log_packet(message):
    # Combines timestamp + message into one formatted log line
    # Example output: [2024-01-15 14:30:25] IP Packet Detected
    # Every packet event is logged with time for the final report
    print(f"[{get_timestamp()}] {message}")