#!/bin/bash
# Startup script for Azure App Service Linux
python -m gunicorn app:app --bind=0.0.0.0:8000 --workers=2 --timeout=120
