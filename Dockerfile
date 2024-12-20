# Base image
FROM python:3.10-slim as base

# Set working directory
WORKDIR /code

# Install dependencies for Java, Git, Androguard, libssl, and yara (required by APKiD)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    wget unzip openjdk-17-jdk git libssl-dev libyara-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy only requirements.txt first to leverage Docker cache
COPY requirements.txt /code/

# Install Python dependencies including androguard and apkid
RUN pip install --upgrade pip && \
    pip install -r requirements.txt --cache-dir=/root/.cache/pip && \
    pip install androguard quark-engine apkid

# Install JADX
RUN wget -q https://github.com/skylot/jadx/releases/download/v1.4.4/jadx-1.4.4.zip && \
    unzip -o -q jadx-1.4.4.zip -d /opt/jadx && \
    ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx && \
    rm jadx-1.4.4.zip

# Copy the Django application
COPY . /code/

# Expose the port
EXPOSE 8001

# Default command to run Django server
CMD ["python", "manage.py", "runserver", "0.0.0.0:8001"]