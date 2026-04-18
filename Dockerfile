FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir . \
    && mkdir -p /data \
    && chmod 0777 /data

USER nobody

ENTRYPOINT ["unifi-dns4me"]
CMD ["daemon"]
