FROM python:3.11-slim

LABEL maintainer="SOC Threat Detection & Log Analyzer"
LABEL description="Containerized SOC log analyzer for brute force / threat detection"

WORKDIR /app

# System deps (build tools needed for optional yara-python)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY rules/ ./rules/
COPY sample_logs/ ./sample_logs/

RUN mkdir -p /app/reports /app/logs

# Default: analyze the bundled sample log and emit all report types.
# Override CMD to point at your own mounted log file, e.g.:
#   docker run -v $(pwd)/mylogs:/app/logs soc-analyzer \
#     --log /app/logs/auth.log --html /app/reports/dashboard.html
ENTRYPOINT ["python3", "src/main.py"]
CMD ["--log", "sample_logs/sample_auth.csv", \
     "--csv", "reports/report.csv", \
     "--html", "reports/dashboard.html", \
     "--pdf", "reports/report.pdf", \
     "--sigma-rules", "rules/sigma"]
