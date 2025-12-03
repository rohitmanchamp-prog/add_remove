FROM python:3.11-slim

WORKDIR /app

# Install system deps (optional but good practice)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
  && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Gunicorn will serve the Flask app on port 8080
ENV PORT=8080
CMD ["gunicorn", "-b", "0.0.0.0:8080", "web_app:app"]