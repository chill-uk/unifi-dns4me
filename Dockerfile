FROM python:slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir . \
    && mkdir -p /data \
    && chmod 0777 /data

ENTRYPOINT ["unifi-dns4me"]
CMD ["daemon"]
