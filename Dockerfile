FROM python:3.11-slim

WORKDIR /app

COPY src/ ./src/

RUN groupadd -r nodpi && useradd -r -g nodpi nodpi

RUN mkdir -p /tmp/nodpi && chown -R nodpi:nodpi /tmp/nodpi

USER nodpi

ENTRYPOINT ["python", "src/main.py"]