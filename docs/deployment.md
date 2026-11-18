# Run and deploy AgentSec Workbench

## Local Compose

Use Docker Engine with Compose v2 or later. Run from the repository root. The existing `.env` is used when present. Scan-only mode works with an empty key.

```sh
docker info
docker compose --env-file .env.example config --quiet
docker compose up -d --build --wait
```

Open [AgentSec Workbench](http://127.0.0.1:8000/). If another process uses that port, start with `AGENTSEC_PORT=8001 docker compose up -d --build --wait` and open port 8001. Choose **Run sample scan** to verify OSV. With an API key configured, generate one recommendation to verify OpenAI. The app publishes its port on loopback, and the named Docker volume stores the SQLite database.

To check health and durable state without sending upstream requests, use the same smoke check as CI. Supply `--base-url` if you changed the port.

```sh
python scripts/container_smoke.py --save /tmp/agentsec-scan-id
docker compose restart
docker compose up -d --wait
python scripts/container_smoke.py --verify /tmp/agentsec-scan-id
docker compose down
```

Use `docker compose logs workbench` to diagnose startup failures. Preserve the volume when updating or stopping an instance whose scans you want to retain.

## Private hosted demo on an existing machine

This prototype supports an SSH-tunneled demo. Requirements are an approved Linux host with SSH, Docker and Compose, outbound access to OSV and OpenAI, and permission to put the repository and a project API key there. Use an existing approved host or obtain approval before provisioning. There is no remote deployment recorded for this repository.

1. Check out a verified commit on the host. Store the API key in the project’s ignored `.env` with restricted file permissions.
2. Start the app with the local Compose commands. Keep the published port on the host’s loopback interface.
3. From your laptop run `ssh -N -L 8001:127.0.0.1:8000 USER@HOST` and open [the tunneled Workbench](http://127.0.0.1:8001/).
4. Confirm that `/health` responds, run the public sample, and verify a recommendation and mock issue approval. Restart the service and verify the scan and review survive. Retain the commit ID and results of these checks.
5. To roll back, check out the previous verified commit and rebuild. Preserve the data volume and take a consistent SQLite backup before changes that affect the schema.

The prototype has no account-based access controls. For a public demo, obtain approval and specify the hosting target, authentication, access scope, TLS, quotas, and secret storage before publishing it.

## CI

The checked-in GitHub Actions workflow uses read-only repository permissions. It runs linting, the Python and MCP tests, deterministic security and evaluation cases, desktop and mobile Chrome tests, and a Docker Compose restart and persistence check. It uses provider test fixtures and needs no OpenAI key. Both jobs passed in [run 44173605698](https://github.com/jarowcavage/agentsec/actions/runs/44173605698). Hosted application deployment is deferred by user choice; the demo remains local.
