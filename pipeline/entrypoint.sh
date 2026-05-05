#!/bin/sh
set -e
python -u -m pipeline.ingestor &
exec python -u -m analytics.scheduler
