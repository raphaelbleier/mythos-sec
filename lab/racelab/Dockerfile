FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
WORKDIR /app
# hypercorn speaks HTTP/2 over TLS with ALPN, which is what the single-packet
# attack needs. Nothing in scripts/ depends on it: it is the target's server.
RUN pip install --no-cache-dir "hypercorn[h2]==0.17.3"
# A throwaway self-signed certificate, generated at build time. The client is
# expected to ignore it (--insecure); the certificate is not the subject here.
RUN openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -subj "/CN=racelab.mythos.lab" \
      -keyout /app/key.pem -out /app/cert.pem 2>/dev/null
COPY app.py /app/app.py
EXPOSE 5000 5443
# A container's own namespace has no route to the host's loopback, so the
# server has to bind 0.0.0.0 here. The compose publish line is what keeps it on
# the host's loopback; run app.py directly and it binds 127.0.0.1 instead.
ENV BIND=0.0.0.0
CMD ["python", "-u", "app.py"]
