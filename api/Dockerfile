FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    REPORTS_DIR=/app/reports

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && adduser --disabled-password --gecos "" honeypot

WORKDIR /app

COPY api/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY pipeline /app/pipeline
COPY analytics /app/analytics
COPY alerting /app/alerting
COPY api /app/api
COPY scripts /app/scripts

COPY api/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh \
    && mkdir -p /app/data /app/reports \
    && chown -R honeypot:honeypot /app

WORKDIR /app/api

EXPOSE 8000

USER root

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
