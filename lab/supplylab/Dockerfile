# Stdlib only: no pip install, so nothing in the image can be confused either.
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
WORKDIR /app
COPY app.py /app/
ENV BIND=0.0.0.0
EXPOSE 5000
CMD ["python", "-u", "app.py"]
