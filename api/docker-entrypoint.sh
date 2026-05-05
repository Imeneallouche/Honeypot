#!/bin/sh
set -e
mkdir -p /app/data /app/reports
chown -R honeypot:honeypot /app/data /app/reports 2>/dev/null || chmod -R o+rwx /app/reports /app/data 2>/dev/null || true
exec runuser -u honeypot -- "$@"
