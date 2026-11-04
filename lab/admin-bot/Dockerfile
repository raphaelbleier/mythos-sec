FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends chromium \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir playwright
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
COPY bot.py /bot.py
EXPOSE 8000
CMD ["python", "-u", "/bot.py"]
