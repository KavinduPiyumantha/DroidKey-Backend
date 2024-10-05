# Base image
FROM python:3.10-slim

# Set working directory
WORKDIR /code

# Copy dependencies file
COPY requirements.txt /code/

# Install dependencies
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Copy the Django application
COPY . /code/

# Expose the port
EXPOSE 8001

# Default command to run Django server
CMD ["python", "manage.py", "runserver", "0.0.0.0:8001"]
