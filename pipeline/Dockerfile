FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

RUN adduser --disabled-password --gecos "" honeypot

WORKDIR /app

COPY pipeline/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY pipeline /app/pipeline
COPY analytics /app/analytics
COPY alerting /app/alerting
COPY scripts /app/scripts

COPY pipeline/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

RUN mkdir -p /app/logs /app/data \
    && chown -R honeypot:honeypot /app

USER honeypot

ENTRYPOINT ["/entrypoint.sh"]
