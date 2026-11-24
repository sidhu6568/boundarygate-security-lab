#!/bin/sh
set -eu
install -m 0644 /solution/authorizer.py /app/boundarygate/authorizer.py
printf '%s\n' 'Installed the BoundaryGate reference repair.'
