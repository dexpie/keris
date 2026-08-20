FROM python:3.11-slim

LABEL org.opencontainers.image.title="Keris"
LABEL org.opencontainers.image.description="Modular web penetration testing toolkit"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Salin dependensi dulu untuk memanfaatkan cache layer
COPY pyproject.toml README.md ./
COPY keris ./keris
COPY keris_enterprise ./keris_enterprise
COPY plugins ./plugins

RUN pip install --no-cache-dir .

# non-root user
RUN useradd -m keris
USER keris

ENTRYPOINT ["keris"]
CMD ["--help"]
