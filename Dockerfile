# Base image
FROM python:3.10-slim

# Set working directory
WORKDIR /code

# Install dependencies needed for Java and JADX
RUN apt-get update && \
    apt-get install -y wget unzip openjdk-17-jdk && \
    rm -rf /var/lib/apt/lists/*

# Install JADX
RUN wget -q https://github.com/skylot/jadx/releases/download/v1.4.4/jadx-1.4.4.zip && \
    unzip -o -q jadx-1.4.4.zip -d /opt/jadx && \
    ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx && \
    rm jadx-1.4.4.zip

# Copy dependencies file
COPY requirements.txt /code/

# Install Python dependencies
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Copy the Django application
COPY . /code/

# Expose the port
EXPOSE 8001

# Default command to run Django server
CMD ["python", "manage.py", "runserver", "0.0.0.0:8001"]
