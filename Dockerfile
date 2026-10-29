# Paradox Detector web app. The core needs only the standard library;
# `anthropic` is installed for the optional Claude analyst summary.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    PARADOX_HOST=0.0.0.0 PARADOX_PORT=8787

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY paradox/ paradox/
COPY web/ web/
COPY server.py .

# History (data/) and bulk-feed caches (.cache/) live on volumes; run unprivileged.
RUN useradd --system --uid 10001 paradox \
 && mkdir -p data .cache && chown paradox data .cache
USER paradox
VOLUME ["/app/data", "/app/.cache"]

EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/healthz', timeout=4)"

CMD ["python", "server.py"]
