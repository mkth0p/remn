FROM python:3.13-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/archive
RUN mkdir -p /var/lib/archive /run/archive \
    && chown 10001:10001 /var/lib/archive /run/archive \
    && chmod 0700 /var/lib/archive /run/archive \
    && rm -rf /usr/local/lib/python3.13/site-packages/pip* /usr/local/bin/pip*
COPY . /opt/archive/honeypot/
USER 10001:10001
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-m", "honeypot.verify", "health"]
CMD ["python", "-m", "honeypot.archive"]
