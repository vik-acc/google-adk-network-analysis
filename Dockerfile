# Use a lightweight official Python image
FROM python:3.11-slim

# Set the base working directory
WORKDIR /app

# 1. Point exactly to the requirements file inside your subfolder
COPY AGENT/requirements.txt .

# 2. Install dependencies (this layer gets cached to save time)
RUN pip install --no-cache-dir -r requirements.txt

# 3. Copy the rest of your repository into the container
COPY . .

# 4. Step into the subfolder so the ADK can find your agent.py
WORKDIR /app/AGENT

# Expose port 8080 for the ADK Web Server
EXPOSE 8080

# Command to boot up the ADK web interface
# CMD ["adk", "web", "--host", "0.0.0.0", "--port", "8080"]
CMD ["adk", "web", "agent.py", "--host", "0.0.0.0", "--port", "8080"]