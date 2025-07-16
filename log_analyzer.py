import re 
import os

FIREWALL_LOG_FILE = "firewall.log"

FIREWALL_LOG_PATTERN = re.compile(
    r"""^(\d{4}\-\d{2}\-\d{2})\s+                    # 1: Date (YYYY-MM-DD)
    (\d{2}\:\d{2}\:\d{2})\s+                         # 2: Time (HH:MM:SS)
    (\w+)\s+                                         # 3: Action (e.g., ALLOW, DENY)
    (\w+)\s+                                         # 4: Protocol (e.g., TCP, UDP, ICMP)
    (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\:\d+)\s+     # 5: Source IP:Port
    (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\:\d+)\s+     # 6: Destination IP:Port
    (.+)$                                            # 7: Reason 
    """, 
    re.VERBOSE  
)
# ---- UTILITY FUNCTION ------
def _extract_ip_and_port(ip_port_str):
    """
    Extracts IP address and port number from a string in 'IP:Port' format.
    Handles ValueError if the format is unexpected.
    """
    try:
        ip, port = ip_port_str.rsplit(':', 1)
        return ip, port
    except ValueError:
        print(f"WARNING: Invalid IP:Port format '{ip_port_str}'. Returning default values.")
        return ip_port_str, "N/A"

# ---- MAIN FUNCTIONS ----
def parse_log_line(log_line, regex_pattern):
    stripped_line = log_line.strip()
    match = regex_pattern.match(stripped_line)

    if match:
        date, time, action, protocol, source_ip_port, dest_ip_port, reason = match.groups()

        source_ip, source_port = _extract_ip_and_port(source_ip_port)
        dest_ip, dest_port     = _extract_ip_and_port(  dest_ip_port)

        log_entry = {
            "date": date,
            "time": time,
            "action": action,
            "protocol": protocol,
            "source_ip": source_ip,       
            "source_port": source_port,   
            "destination_ip": dest_ip,    
            "destination_port": dest_port,
            "reason": reason
        }
        return log_entry
    else:
        return None


def load_logs_from_file(file_path, regex_pattern):
    parsed_logs = []
    if not os.path.exists(file_path):
        print(f"Error: The file '{file_path}' was not found.")
        return []

    try:
        with open(file_path, "r") as file:
            print(f"Reading file: {file_path}")
            for line in file:
                log_entry = parse_log_line(line, regex_pattern)
                if log_entry:
                    parsed_logs.append(log_entry)
                else:
                    print(f"WARNING: Line did not match pattern: {line.strip()}")
        print(f"\nRead finished. Processed {len(parsed_logs)} valid entries.")
        return parsed_logs
    except Exception as e:
        print(f"An unexpected error occurred while reading the file '{file_path}': {e}")
        return []

def generate_denied_traffic_summary(parsed_logs):
    denied_count = 0
    denied_ips = set()
    denied_details = []

    print("\n--- DENIED TRAFFIC SUMMARY ---")
    if not parsed_logs:
        print("No log entries to analyze.")
        return
    
    for entry in parsed_logs:
        if entry["action"] == "DENY":
            denied_count += 1
            denied_ips.add(entry["source_ip"]) 
            denied_details.append(
                f"  DENIED: {entry['source_ip']} tried to reach {entry['destination_ip']}:"
                f"{entry['destination_port']} (Protocol: {entry['protocol']}) - Reason: {entry['reason']}"
            )

    if(denied_details):
        for detail in denied_details:
            print(detail)
    else:
        print("No denied traffic found.")
    
    print(f"\nTotal DENIED entries: {denied_count}")
    print(f"Unique Source IPs involved in DENIED traffic: {len(denied_ips)}")

    if denied_ips:
        print("Denied Source IPs:")
        for ip in sorted(list(denied_ips)): 
            print(f"  - {ip}")

def display_first_entries(parsed_logs, count=3):
    if parsed_logs:
        print(f"\nTotal parsed log entries: {len(parsed_logs)}")
        print(f"First {count} parsed entries:")
        for i, entry in enumerate(parsed_logs[:count]): 
            print(f"Entry {i+1}: {entry}")
    else:
        print("No log entries were parsed.")

if __name__ == "__main__":
    # 1. Load logs from the file
    firewall_logs = load_logs_from_file(FIREWALL_LOG_FILE, FIREWALL_LOG_PATTERN)

    # 2. Generate summary of denied traffic
    generate_denied_traffic_summary(firewall_logs)

    # 3. Display the first parsed entries
    display_first_entries(firewall_logs, 3)