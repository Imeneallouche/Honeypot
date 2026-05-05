FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

RUN apt-get update \
    && apt-get install -y --no-install-recommends netcat-openbsd \
    && rm -rf /var/lib/apt/lists/* \
    && adduser --disabled-password --gecos "" honeypot

WORKDIR /app

COPY honeypots/ssh/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY pipeline/__init__.py /app/pipeline/__init__.py
COPY pipeline/logger.py /app/pipeline/logger.py

COPY honeypots/__init__.py /app/honeypots/__init__.py
COPY honeypots/base.py /app/honeypots/base.py
COPY honeypots/config.py /app/honeypots/config.py

COPY honeypots/ssh/server.py /app/honeypots/ssh/server.py
COPY honeypots/ssh/session.py /app/honeypots/ssh/session.py
COPY honeypots/ssh/fake_shell.py /app/honeypots/ssh/fake_shell.py
COPY honeypots/ssh/host_key.py /app/honeypots/ssh/host_key.py
COPY honeypots/ssh/__init__.py /app/honeypots/ssh/__init__.py

RUN mkdir -p /app/logs /app/data \
    && chown -R honeypot:honeypot /app

USER honeypot
WORKDIR /app/honeypots/ssh

CMD ["python", "server.py"]
