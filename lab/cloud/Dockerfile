FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
WORKDIR /app
RUN pip install --no-cache-dir flask==3.1.3 requests==2.34.2
COPY app.py metadata.py /app/
EXPOSE 5000 80
CMD ["python", "-u", "app.py"]
