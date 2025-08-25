# Network Quality Monitor

This Python script is a robust tool for continuously monitoring your network connection and application performance. It gathers key metrics, provides real-time console feedback, generates logs, and exposes all data to a Prometheus endpoint for advanced monitoring and graphing.

## 📝 Features

- Network Health Metrics: Tracks ping latency, packet loss percentage, and the path (traceroute) to a configured internet host.
- System-Level Monitoring: Uses the psutil library for reliable, cross-platform tracking of total bytes sent and received, as well as the total number of packets dropped by your system.
- Application Performance: Measures the response time of a specified web application or API endpoint using an HTTP request.
- Prometheus Integration: Exposes all collected metrics on a dedicated HTTP server, making it easy to integrate with your existing Prometheus and Grafana setup.
- Real-time Alerts: Plays sound alerts for degraded network performance (yellow alert for partial loss) or a complete outage (red alert for 100% loss).
- Logging: Automatically logs significant network events to a text file for post-analysis.

##⚙️ Requirements & Installation
This script requires several Python libraries and system-level tools.

## 1. Python Libraries

First, ensure you have Python 3 installed on your system. Then, install the required libraries using pip and the requirements.txt file provided below.

requirements.txt
```
    prometheus_client==0.22.1
    psutil
    requests
    pydub==0.25.1
    simpleaudio==1.0.4
```

To install all dependencies, run the following command in your terminal:pip install -r requirements.txt

## 2. System-Level Tools

- traceroute / tracert: A network diagnostic tool for displaying the path and measuring transit delays of packets across an IP network. This is usually pre-installed on most operating systems.
- whois: A command-line utility for performing WHOIS lookups.
- afplay (macOS): A native command for playing audio files. If you are using Windows or Linux, you may need to adjust the play_sound_mac function to use a different command or library.

## 🚀 Usage
### 1. Configuration
You can customize the script by editing the variables at the top of network_monitor.py.

- INTERNET_HOST: The IP address or domain to use for network health checks (default: 8.8.8.8).
- APPLICATION_URL: The full URL for application response time checks (default: https://www.google.com).
- INTERVAL: The time in seconds between each monitoring check (default: 10).
- PROMETHEUS_PORT: The port on which the Prometheus metrics server will listen (default: 8000).
- SOUND_ENABLED: Set to True or False to enable or disable sound alerts.
- YELLOW_SOUND_PATH & RED_SOUND_PATH: The file paths to your .wav sound files.2. 

### Running the Script
To start the network monitoring, simply run the script from your terminal:python 
```
network_monitor.py
```

The script will begin printing real-time status updates to the console and will expose metrics on the configured Prometheus port. Press Ctrl+C to stop the monitoring.

## 📊 Prometheus Metrics

The script exposes the following metrics on the specified port (default: 8000), which you can scrape with a Prometheus server.

```
# HELP network_ping_latency_ms Ping latency in milliseconds to the internet host.
# TYPE network_ping_latency_ms gauge
network_ping_latency_ms 12.34

# HELP network_packet_loss_percent Packet loss percentage to the internet host.
# TYPE network_packet_loss_percent gauge
network_packet_loss_percent 0.0

# HELP network_application_response_time_ms Application response time in milliseconds.
# TYPE network_application_response_time_ms gauge
network_application_response_time_ms 25.56

# HELP network_bytes_received_total Total bytes received on the network interface.
# TYPE network_bytes_received_total gauge
network_bytes_received_total 123456789.0

# HELP network_bytes_transmitted_total Total bytes transmitted on the network interface.
# TYPE network_bytes_transmitted_total gauge
network_bytes_transmitted_total 987654321.0

# HELP network_packets_dropped_total Total packets dropped on the network interface.
# TYPE network_packets_dropped_total gauge
network_packets_dropped_total 5.0
```

## 📄 Logging

The script creates two log files to help you with post-mortem analysis:
- connection_log.txt: Records the date and time of any degraded or failed network checks.
- traceroute_log.txt: Stores the complete output of every traceroute command for a detailed view of your network path over time.

## 📄 License
This project is licensed under the MIT License - see the LICENSE.md file for details.