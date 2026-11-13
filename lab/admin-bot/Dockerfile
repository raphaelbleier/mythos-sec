FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
RUN apt-get update && apt-get install -y --no-install-recommends chromium \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir playwright==1.65.1
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
COPY bot.py /bot.py
EXPOSE 8000
CMD ["python", "-u", "/bot.py"]
