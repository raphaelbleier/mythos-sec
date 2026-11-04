# Mythos lab

Deliberately vulnerable targets on the isolated docker network `mythos-lab`. Local use only.

    docker compose -f lab/docker-compose.yml up -d            # everything
    docker compose -f lab/docker-compose.yml up -d vulnapp    # one target
    scripts/mythos net mythos-lab                             # toolbox joins the lab network

From the toolbox, targets resolve by service name (`http://vulnapp:5000`, `http://juiceshop:3000`),
or via `http://host.docker.internal:<published port>`.

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
