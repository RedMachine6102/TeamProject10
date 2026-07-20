FROM python:3.13-alpine@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0 AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN addgroup -S vaultmind && \
    adduser -S -D -H -u 999 -G vaultmind vaultmind
WORKDIR /app
COPY requirements.lock pyproject.toml README.md ./
RUN python -m pip install --no-deps -r requirements.lock
COPY src ./src
COPY web ./web
COPY scripts/generate_sbom.py /tmp/generate_sbom.py
RUN python -m pip install --no-build-isolation --no-deps . && \
    python -m pip uninstall -y pip setuptools wheel jaraco.context && \
    python /tmp/generate_sbom.py /app/sbom.spdx.json && \
    rm /tmp/generate_sbom.py
RUN mkdir -p /app/data /app/backups && \
    chown -R vaultmind:vaultmind /app/data /app/backups

USER vaultmind
EXPOSE 8080
CMD ["uvicorn", "vaultmind_next.api:app", "--host", "0.0.0.0", "--port", "8080", "--no-server-header"]
