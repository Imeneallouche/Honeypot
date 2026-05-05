FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

RUN apt-get update \
    && apt-get install -y --no-install-recommends netcat-openbsd \
    && rm -rf /var/lib/apt/lists/* \
    && adduser --disabled-password --gecos "" honeypot

WORKDIR /app

COPY honeypots/http/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY analytics/__init__.py /app/analytics/__init__.py
COPY analytics/payloads.py /app/analytics/payloads.py

COPY pipeline/__init__.py /app/pipeline/__init__.py
COPY pipeline/logger.py /app/pipeline/logger.py

COPY honeypots/__init__.py /app/honeypots/__init__.py
COPY honeypots/base.py /app/honeypots/base.py
COPY honeypots/config.py /app/honeypots/config.py

COPY honeypots/http/server.py /app/honeypots/http/server.py
COPY honeypots/http/routes.py /app/honeypots/http/routes.py
COPY honeypots/http/fingerprint.py /app/honeypots/http/fingerprint.py
COPY honeypots/http/__init__.py /app/honeypots/http/__init__.py
COPY honeypots/http/templates /app/honeypots/http/templates

RUN mkdir -p /app/logs \
    && chown -R honeypot:honeypot /app

USER honeypot
WORKDIR /app/honeypots/http

CMD ["python", "server.py"]
