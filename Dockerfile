# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Install system dependencies required for ping, traceroute, whois, curl, and ip
# We also install build-essential and libasound2-dev to build simpleaudio
RUN apt-get update && \
    apt-get install -y iputils-ping traceroute whois curl iproute2 build-essential libasound2-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy the requirements file and install dependencies
# We copy this first to leverage Docker's layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy only the main script
COPY network_monitor.py .

# Expose the Prometheus metrics port
EXPOSE 8000

# Command to run the script when the container starts
CMD ["python", "./network_monitor.py"]