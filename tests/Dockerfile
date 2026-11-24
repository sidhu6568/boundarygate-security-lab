FROM docker.io/library/python:3.12.14-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONNOUSERSITE=1

COPY contract/boundarygate /opt/boundary-contract/boundarygate
COPY candidate_host.py /opt/boundary-runner/candidate_host.py
COPY verifier.py test.sh /tests/

RUN mkdir -p /app/boundarygate /logs/verifier \
    && chmod -R a=rX /opt/boundary-contract /opt/boundary-runner \
    && chmod 0700 /tests /tests/test.sh /logs/verifier \
    && chmod 0600 /tests/verifier.py

WORKDIR /tests
