# Paradox Detector, headless. Installs the `paradox` command; the image runs
# `paradox serve` (web UI + JSON API) by default, and any other subcommand
# works too: docker run --rm IMAGE paradox scan 1.2.3.4 --json
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    PARADOX_HOME=/var/lib/paradox PARADOX_HOST=0.0.0.0 PARADOX_PORT=8787

WORKDIR /src
COPY pyproject.toml README.md ./
COPY paradox/ paradox/
# The [narrative] extra adds the optional Claude analyst summary.
RUN pip install --no-cache-dir ".[narrative]" && rm -rf /src

# History and bulk-feed caches live on a volume; run unprivileged.
RUN useradd --system --uid 10001 paradox \
 && mkdir -p /var/lib/paradox && chown paradox /var/lib/paradox
USER paradox
WORKDIR /var/lib/paradox
VOLUME ["/var/lib/paradox"]

EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/healthz', timeout=4)"

CMD ["paradox", "serve"]
