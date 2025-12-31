# syntax=docker/dockerfile:1

FROM python:3.11-slim

# Prevents Python from writing pyc files and enables unbuffered logs
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install Python deps first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app files (app.py serves main.html from the same directory)
COPY app.py main.html README.md ./

# App listens on PORT; we'll run it on 4000
ENV HOST=0.0.0.0 \
    PORT=4000

EXPOSE 4000

# Simple healthcheck (your app provides /api/health)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS http://127.0.0.1:4000/api/health || exit 1

# Run the app
CMD ["python", "app.py"]
