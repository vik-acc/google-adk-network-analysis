FROM python:3.11-slim
WORKDIR /app

# 1. Install dependencies from the subfolder
COPY AGENT/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 2. Copy the whole project
COPY . .

# 3. STAY in the root directory (/app)
# 4. Run adk web ON the AGENT folder
EXPOSE 8080
CMD ["adk", "web", "AGENT", "--host", "0.0.0.0", "--port", "8080"]