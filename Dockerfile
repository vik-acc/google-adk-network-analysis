FROM python:3.11-slim
WORKDIR /app

# 1. Install dependencies from the subfolder
COPY AGENT/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 2. Copy everything
COPY . .

# 3. MOVE into the AGENT folder before starting
WORKDIR /app/AGENT

# 4. Start the web server looking at the current directory (.)
EXPOSE 8080
CMD ["adk", "web", ".", "--host", "0.0.0.0", "--port", "8080"]