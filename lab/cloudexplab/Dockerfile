# Stdlib only: no pip install, so this image needs no network to build beyond
# the base layer, and `python3 lab/cloudexplab/app.py` runs identically on the
# host (which is how `scripts/cloudexp selftest` drives it).
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
WORKDIR /app
COPY app.py /app/
EXPOSE 5000
# 0.0.0.0 inside the container only; compose publishes it on the host's
# loopback (${MYTHOS_LAB_BIND:-127.0.0.1}:5025:5000).
CMD ["python", "-u", "app.py", "--port", "5000", "--bind", "0.0.0.0"]
