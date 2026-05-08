# Use official Python runtime
FROM python:3.11-slim

# Set the working directory
WORKDIR /app

# Copy your scripts and requirement files
COPY . /app

# Install the dependencies
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install google-adk

# Expose the port the ADK web server uses
EXPOSE 8080

# Command to run the ADK web server automatically
CMD ["adk", "web", "--host", "0.0.0.0", "--port", "8080"]