#!/usr/bin/env bash
set -e

echo "Startup Services"
service clamav-daemon start
service clamav-freshclam start
service uwsgi start
service nginx start
echo "ready to go"