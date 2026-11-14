# Mythos lab

Deliberately vulnerable targets on the isolated docker network `mythos-lab`. Local use only.

    docker compose -f lab/docker-compose.yml up -d            # everything
    docker compose -f lab/docker-compose.yml up -d vulnapp    # one target
    mythos -t http://127.0.0.1:5001                           # run against one

Every service publishes on the host's loopback only. A bridged container cannot
reach the host loopback at any address, so the CLI puts the toolbox in the host's
network namespace for a `127.0.0.1` target (`MYTHOS_NET=host`), and the target
keeps its `127.0.0.1` address inside the container. Host networking removes the
isolation between the container and this machine, which is acceptable for a local
lab and for nothing else.

To work inside the lab's own network instead, attach the bridged toolbox with
`scripts/mythos net mythos-lab`; targets then resolve by service name
(`http://vulnapp:5000`, `http://juiceshop:3000`), and the host is reached as
`host.docker.internal:<published port>`.

| service | host port | notes |
|---|---|---|
| vulnapp | 5001 | ground truth |
| juiceshop | 3000 | |
| dvwa | 4280 | |
| vampi | 5002 | |
| dvga | 5013 | GraphQL |
| vuln-bank-web | 5003 | needs a checkout: `git clone https://github.com/Commando-X/vuln-bank "$VULNBANK_DIR"` (default `/mnt/linux-data/mythos-bench/vuln-bank`) |
| oast | 8081 | HTTP catcher on 8080 (in-lab `http://oast:8080/<anything>`), DNS on 5353/udp; `GET /__log` dumps JSONL of all hits |
| admin-bot | 8000 | `POST /visit {"url": "http://vuln-bank-web:5000/..."}`; visits as admin using `ADMIN_COOKIE_NAME`/`ADMIN_COOKIE_VALUE`; only hosts in `ALLOWED_HOSTS` |

The oast DNS listener answers every A query with `OAST_IP` (default 127.0.0.1); it is a logger, not a resolver.
