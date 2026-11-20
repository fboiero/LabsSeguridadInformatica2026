FROM projectdiscovery/httpx@sha256:f8275a7c6aaec187249df9eaf4ad9196f4677adfc6a51a47b4aaa1d4db4f8ffc AS httpx
FROM projectdiscovery/subfinder@sha256:2f5ddea311db2a8b848e40f1b669fc655d0eb78b74a74ead93d3850e372b12bf AS subfinder
FROM python@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89
RUN pip install --no-cache-dir PyYAML==6.0.3 pytest==9.2.0
COPY --from=httpx /usr/local/bin/httpx /usr/local/bin/httpx
COPY --from=subfinder /usr/local/bin/subfinder /usr/local/bin/subfinder
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUTF8=1
WORKDIR /work
CMD ["sleep", "infinity"]
