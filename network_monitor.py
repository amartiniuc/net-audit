import os
import time
from datetime import datetime
import platform
import subprocess
import re
import threading
import sys

# Import Prometheus client library for exposing metrics
try:
    from prometheus_client import Gauge, start_http_server
except ImportError:
    print("Prometheus client library not found. Please install it using: pip install prometheus_client")
    sys.exit(1)

# Import psutil for reliable network stats
try:
    import psutil
except ImportError:
    print("psutil library not found. Please install it using: pip install psutil")
    sys.exit(1)

# Import requests for measuring application response time
try:
    import requests
except ImportError:
    print("requests library not found. Please install it using: pip install requests")
    sys.exit(1)

# --- Configuration ---
# The internet host to use for the full network audit (ping and traceroute).
INTERNET_HOST = "8.8.8.8"

# The URL of the application to check for response time.
APPLICATION_URL = "https://www.google.com"

# The name of the log file where results will be stored.
LOG_FILE = "connection_log.txt"

# The time to wait between each check (in seconds).
INTERVAL = 10

# The port for the Prometheus metrics endpoint.
PROMETHEUS_PORT = 8000

# Set this to True to print the shell commands being executed.
VERBOSE = True

# --- ANSI Color Codes for Console Output ---
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'

# --- Sound File Configuration ---
# Make sure to set these paths to your .wav file locations.
SOUND_ENABLED = True
YELLOW_SOUND_PATH = "yellow_alert.wav" # Replace with your .wav file
RED_SOUND_PATH = "red_alert.wav" # Replace with your .wav file

# --- Prometheus Metrics ---
# We will use Gauge metrics, which can go up and down.
PING_LATENCY_GAUGE = Gauge('network_ping_latency_ms', 'Ping latency in milliseconds to the internet host.')
PACKET_LOSS_GAUGE = Gauge('network_packet_loss_percent', 'Packet loss percentage to the internet host.')
TRACEROUTE_HOPS_GAUGE = Gauge('network_traceroute_hops', 'Number of successful hops in the traceroute path.')
TRACEROUTE_HOP_LATENCY = Gauge('network_traceroute_hop_latency_ms', 'Latency for each hop in the traceroute path.', ['hop', 'ip', 'hostname'])
bytes_received_gauge = Gauge('network_bytes_received_total', 'Total bytes received on the network interface.')
bytes_transmitted_gauge = Gauge('network_bytes_transmitted_total', 'Total bytes transmitted on the network interface.')
APPLICATION_RESPONSE_TIME_GAUGE = Gauge('network_application_response_time_ms', 'Application response time in milliseconds.')
packets_dropped_gauge = Gauge('network_packets_dropped_total', 'Total packets dropped on the network interface.')


# --- Sound Playback Function (macOS specific) ---
def play_sound_mac(file_path):
    """
    Plays a sound file using the native macOS 'afplay' command.
    """
    try:
        # Popen is used to avoid blocking the main script
        subprocess.Popen(['afplay', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception as e:
        print(f"Error playing sound with afplay: {e}")

def check_connection(host):
    """
    Pings a single host and returns a dictionary with connection metrics.
    Metrics include: success, packet_loss_percent, and avg_latency_ms.
    """
    system_os = platform.system()
    try:
        if system_os == 'Windows':
            # Ping with 4 packets and capture output
            command = ['ping', '-n', '4', host]
        else:  # Linux, macOS, etc.
            # Ping with 4 packets and capture output
            command = ['ping', '-c', '4', host]
        
        if VERBOSE:
            print(f"Executing command: {' '.join(command)}")

        process = subprocess.run(command, capture_output=True, text=True, timeout=10)
        output = process.stdout
        
        if system_os == 'Windows':
            # Use regex to find packet loss and average latency
            packet_loss_match = re.search(r'\((\d+)% loss\)', output)
            avg_latency_match = re.search(r'Average = (\d+)ms', output)
            
            packet_loss = int(packet_loss_match.group(1)) if packet_loss_match else 100
            avg_latency = int(avg_latency_match.group(1)) if avg_latency_match else -1
            
        else:  # Linux, macOS, etc.
            # Use regex to find packet loss and average latency
            packet_loss_match = re.search(r'(\d+)% packet loss', output)
            avg_latency_match = re.search(r'min/avg/max/mdev = [\d.]+/([\d.]+)/[\d.]+/[\d.]+ ms', output)

            packet_loss = int(packet_loss_match.group(1)) if packet_loss_match else 100
            # Convert average latency to integer
            avg_latency = float(avg_latency_match.group(1)) if avg_latency_match else -1

        success = packet_loss < 100
        return {
            "success": success,
            "packet_loss": packet_loss,
            "avg_latency": avg_latency
        }

    except (subprocess.TimeoutExpired, FileNotFoundError, IndexError, ValueError):
        # If ping command fails or parsing errors, assume 100% loss
        return {
            "success": False,
            "packet_loss": 100,
            "avg_latency": -1
        }

def get_whois_info(ip_address):
    """
    Performs a WHOIS lookup for a given IP address and returns a dictionary
    of relevant information.
    """
    whois_info = {
        "org_name": "N/A",
        "country": "N/A"
    }

    # Check if the IP is a private address
    if ip_address.startswith(("192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")):
        return whois_info

    try:
        # This requires the 'whois' command-line tool to be installed
        whois_output = subprocess.check_output(['whois', ip_address], text=True, timeout=5)
        
        # Regex to find key information
        org_name_match = re.search(r'(OrgName|organization|descr):\s+(.+)', whois_output, re.IGNORECASE)
        country_match = re.search(r'(Country|country):\s+(.+)', whois_output, re.IGNORECASE)

        if org_name_match:
            whois_info["org_name"] = org_name_match.group(2).strip()
        
        if country_match:
            whois_info["country"] = country_match.group(2).strip()

    except (subprocess.TimeoutExpired, FileNotFoundError, IndexError, ValueError, subprocess.CalledProcessError):
        # If whois command fails or parsing errors
        pass # Return the default "N/A" values
    
    return whois_info

def run_traceroute(host):
    """
    Performs a traceroute to the specified host and returns a list of hops with
    latency, hostnames, and WHOIS information.
    """
    system_os = platform.system()
    traceroute_results = []
    
    try:
        # Removed the -n flag to enable reverse DNS lookup for hostnames
        if system_os == 'Windows':
            command = ['tracert', '-w', '1000', host]  # -w sets timeout to 1 sec
        else:
            command = ['traceroute', '-w', '1', host] # -w sets timeout to 1 sec
        
        if VERBOSE:
            print(f"Executing command: {' '.join(command)}")

        # Log the full traceroute output to a separate file for debugging
        full_traceroute_output = subprocess.check_output(command, text=True, timeout=10)
        with open("traceroute_log.txt", "a") as f:
            f.write(f"\n--- Traceroute to {host} at {datetime.now()} ---\n")
            f.write(full_traceroute_output)

        # Process the output for the console and log
        lines = full_traceroute_output.splitlines()

        for line in lines:
            if not line:
                continue
            
            # Windows output parsing
            if system_os == 'Windows':
                match = re.search(r'^\s*(\d+)\s+[\d.<*]+ms\s+[\d.<*]+ms\s+[\d.<*]+ms\s+([a-zA-Z0-9.-]+)\s+\[([\d.]+|Request)\]', line)
                if match:
                    hop_num = int(match.group(1))
                    hostname = match.group(2)
                    ip_address = match(3).strip()
                    whois_info = get_whois_info(ip_address)
                    traceroute_results.append({
                        "hop": hop_num,
                        "hostname": hostname,
                        "ip": ip_address,
                        "latency": -1, # No simple latency data
                        "whois": whois_info
                    })
                elif re.search(r'^\s*(\d+)\s+\* \*\s*\*.*', line):
                    hop_num = int(line.strip().split()[0])
                    traceroute_results.append({
                        "hop": hop_num,
                        "hostname": "Timed Out",
                        "ip": "Timed Out",
                        "latency": -1,
                        "whois": {"org_name": "N/A", "country": "N/A"}
                    })

            # Unix/Linux/macOS output parsing
            else:
                match = re.search(r'^\s*(\d+)\s+([^\s]+)\s+\(([\d.]+)\).*?([\d.]+) ms', line)
                if match:
                    hop_num = int(match.group(1))
                    hostname = match.group(2)
                    ip_address = match.group(3)
                    latency = float(match.group(4))
                    whois_info = get_whois_info(ip_address)
                    traceroute_results.append({
                        "hop": hop_num,
                        "hostname": hostname,
                        "ip": ip_address,
                        "latency": latency,
                        "whois": whois_info
                    })
                elif re.search(r'^\s*\d+\s+\* \*\s*\*.*', line):
                    hop_num = int(line.strip().split()[0])
                    traceroute_results.append({
                        "hop": hop_num,
                        "hostname": "Timed Out",
                        "ip": "Timed Out",
                        "latency": -1,
                        "whois": {"org_name": "N/A", "country": "N/A"}
                    })

    except (subprocess.TimeoutExpired, FileNotFoundError, IndexError, ValueError, subprocess.CalledProcessError):
        traceroute_results.append({
            "hop": -1,
            "hostname": "Traceroute Failed",
            "ip": "Traceroute Failed",
            "latency": -1,
            "whois": {"org_name": "N/A", "country": "N/A"}
        })

    return traceroute_results


def get_network_interface_stats():
    """
    Uses the psutil library to get total network bytes received and transmitted,
    as well as total packets dropped.
    This is a cross-platform and reliable method.
    """
    try:
        # Get total network I/O counters for all interfaces
        net_io = psutil.net_io_counters(pernic=False, nowrap=True)
        if net_io:
            bytes_received_gauge.set(net_io.bytes_recv)
            bytes_transmitted_gauge.set(net_io.bytes_sent)
            packets_dropped_gauge.set(net_io.dropin + net_io.dropout)
            print(f"Network stats: Received {net_io.bytes_recv} bytes, Transmitted {net_io.bytes_sent} bytes. Dropped packets: {net_io.dropin + net_io.dropout}")
        else:
            print("Could not retrieve network I/O counters.")
            bytes_received_gauge.set(0)
            bytes_transmitted_gauge.set(0)
            packets_dropped_gauge.set(0)
    except Exception as e:
        print(f"Error getting network stats with psutil: {e}")
        bytes_received_gauge.set(0)
        bytes_transmitted_gauge.set(0)
        packets_dropped_gauge.set(0)

def check_application_response_time(url):
    """
    Measures the response time of a web application or API endpoint.
    Returns the latency in milliseconds or -1 on failure.
    """
    try:
        # Measure the time it takes to get a response
        start_time = time.time()
        response = requests.get(url, timeout=5)
        end_time = time.time()
        response_time = (end_time - start_time) * 1000 # Convert to milliseconds
        response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
        return response_time
    except requests.exceptions.RequestException as e:
        print(f"Error checking application response time for {url}: {e}")
        return -1


def main():
    """
    Main function to run the network monitoring loop.
    This version checks the internet connection and performs a full traceroute
    audit to determine network health, while also exposing metrics for Prometheus.
    """
    print("Starting network connection quality monitoring...")
    print(f"Checking connections every {INTERVAL} seconds. Press Ctrl+C to stop.")

    # Start the Prometheus metrics server in the background
    start_http_server(PROMETHEUS_PORT)
    print(f"Prometheus metrics exposed on port {PROMETHEUS_PORT}.")

    # Check and play sounds at the start to confirm they work
    print("Testing sound alerts...")
    if SOUND_ENABLED:
        try:
            play_sound_mac(YELLOW_SOUND_PATH)
            time.sleep(1) # Wait for sound to finish
            play_sound_mac(RED_SOUND_PATH)
            time.sleep(1) # Wait for sound to finish
            print("Sound test complete.")
        except Exception as e:
            print(f"Sound test failed: {e}")
            
    # Write a header to the log file to make it easier to read later.
    with open(LOG_FILE, "a") as f:
        f.write("--- Network Quality Monitoring Log --- \n")
        f.write(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Monitoring host: {INTERNET_HOST}\n")
        f.write("-------------------------------------\n")

    try:
        while True:
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Check internet ping and perform traceroute
            internet_ping_result = check_connection(INTERNET_HOST)
            traceroute_results = run_traceroute(INTERNET_HOST)
            get_network_interface_stats()
            application_response_time = check_application_response_time(APPLICATION_URL)

            # Determine overall status based on the internet ping
            packet_loss = internet_ping_result['packet_loss']
            
            # Update Prometheus metrics with the latest data
            PING_LATENCY_GAUGE.set(internet_ping_result['avg_latency'])
            PACKET_LOSS_GAUGE.set(packet_loss)
            TRACEROUTE_HOPS_GAUGE.set(len(traceroute_results))
            
            if application_response_time != -1:
                APPLICATION_RESPONSE_TIME_GAUGE.set(application_response_time)
                
            # Clear previous hop latencies before updating
            TRACEROUTE_HOP_LATENCY.clear()
            for hop in traceroute_results:
                if hop['latency'] != -1:
                    TRACEROUTE_HOP_LATENCY.labels(
                        hop=str(hop['hop']),
                        ip=hop['ip'],
                        hostname=hop['hostname']
                    ).set(hop['latency'])

            # Determine color based on overall status
            if packet_loss == 0:
                color = GREEN
            elif packet_loss > 0 and packet_loss < 100:
                color = YELLOW
                if SOUND_ENABLED:
                    # Use a thread to play the sound asynchronously to avoid blocking
                    threading.Thread(target=play_sound_mac, args=(YELLOW_SOUND_PATH,), daemon=True).start()
            else:
                color = RED
                if SOUND_ENABLED:
                    # Use a thread to play the sound asynchronously to avoid blocking
                    threading.Thread(target=play_sound_mac, args=(RED_SOUND_PATH,), daemon=True).start()
            
            # Prepare verbose console output
            console_output = f"\n{current_time}"
            console_output += f"\n--------------------------------------------"
            
            # Report on internet connection
            if internet_ping_result['success']:
                console_output += f"\n- The internet connection is STABLE."
                console_output += f" Latency is at {internet_ping_result['avg_latency']}ms with {packet_loss}% packet loss."
            else:
                console_output += f"\n- The internet connection is DOWN."
                console_output += f" There is {packet_loss}% packet loss to the internet, indicating a complete outage."

            # Report on application response time
            if application_response_time != -1:
                console_output += f"\n- The application response time for {APPLICATION_URL} is {application_response_time:.2f}ms."
            else:
                console_output += f"\n- Failed to get application response time for {APPLICATION_URL}."

            # Add traceroute results with a more descriptive summary
            if traceroute_results:
                console_output += f"\n\nPath to {INTERNET_HOST}:"
                for hop in traceroute_results:
                    if hop['latency'] != -1:
                        console_output += f"\n  Hop {hop['hop']}: {hop['hostname']} ({hop['ip']}) ({hop['latency']}ms)"
                    else:
                        console_output += f"\n  Hop {hop['hop']}: {hop['hostname']} ({hop['ip']})"
                    
                    if hop['whois']['org_name'] != "N/A":
                        console_output += f"\n    - Owned by: {hop['whois']['org_name']}, Country: {hop['whois']['country']}"
            
            print(f"{color}{console_output}{RESET}")

            # Log a message to the file if there's any packet loss or a timed-out hop
            if packet_loss > 0 or any(hop['latency'] == -1 for hop in traceroute_results):
                with open(LOG_FILE, "a") as f:
                    f.write(console_output + "\n")
            
            # Wait for the specified interval before the next check.
            time.sleep(INTERVAL)

    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")
        with open(LOG_FILE, "a") as f:
            f.write(f"\nStopped at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
if __name__ == "__main__":
    main()
