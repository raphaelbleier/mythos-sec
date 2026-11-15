FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
WORKDIR /app
# stdlib only: the fixture serves static bytes, so there is nothing to install.
COPY app.py /app/
ENV SBOMLAB_HOST=0.0.0.0
EXPOSE 5000
CMD ["python", "-u", "app.py"]
