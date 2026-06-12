FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap tcpdump libpcap-dev net-tools iproute2 \
    libcap2-bin wireless-tools curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Grant raw socket caps inside container
RUN setcap cap_net_raw,cap_net_admin+eip /usr/bin/python3.11 2>/dev/null || true
RUN setcap cap_net_raw,cap_net_admin+eip /usr/sbin/tcpdump 2>/dev/null || true
COPY app.py .
EXPOSE 8000
CMD ["python", "app.py"]
