# --- Stage 1: Build Frontend ---
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# --- Stage 2: Backend & Runtime ---
FROM python:3.12-slim
WORKDIR /app

# Install system dependencies for Scapy and Networking
RUN apt-get update && apt-get install -y \
    libcap2-bin \
    libpcap-dev \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Copy backend
COPY backend/ /app/backend/
WORKDIR /app/backend
RUN pip install --no-cache-dir -r requirements.txt

# Copy built frontend
COPY --from=frontend-builder /app/frontend/dist /app/frontend/dist

# Copy root runner
WORKDIR /app
COPY run.py /app/run.py

# Expose ports
EXPOSE 8000 5173

# We will use a simple server for the frontend dist in production mode
# or just run the dev server if requested.
# For true portability, we'll use a unified entrypoint.
CMD ["python", "run.py", "backend"]
