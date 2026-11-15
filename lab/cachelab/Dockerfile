FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
WORKDIR /app
COPY cachelab.py /app/cachelab.py
# Stdlib only: no pip install, nothing to pin beyond the base image digest.
EXPOSE 5000 5001
ENV CACHELAB_ALLOW_ANY_BIND=1
CMD ["python", "-u", "cachelab.py", "--bind", "0.0.0.0", \
     "--edge-port", "5000", "--origin-port", "5001"]
