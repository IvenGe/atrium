# Atrium in a container. With Docker Compose (docker-compose.yml):
#
#     docker compose up -d --build
#     docker compose logs atrium        # shows the one-time first-run setup link
#
# Without Compose: docker build -t atrium . && docker run -d -p 127.0.0.1:8710:8710 -v atrium-data:/data atrium
# The hub's database, cloned tools, adapters and patch worktrees live in the /data volume.
ARG PYTHON_VERSION=3.13
FROM python:${PYTHON_VERSION}-slim

# git: importing tools and code patches; openssh-client: hosts reached over SSH.
RUN apt-get update \
    && apt-get install --yes --no-install-recommends git openssh-client \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

WORKDIR /opt/atrium
COPY pyproject.toml README.md ./
COPY hub ./hub
RUN pip install ".[ai,ssh]"

# Named volumes start out with the ownership of /data in the image, so the hub can write there as this user.
RUN useradd --create-home --uid 1000 --user-group atrium \
    && mkdir -p /data \
    && chown atrium:atrium /data

# Inside the container the hub listens on all interfaces; publish the port on 127.0.0.1 (see docker-compose.yml)
# or behind a TLS reverse proxy. HUB_PUBLIC_URL is what the setup link and the SSO redirect URI use.
ENV HUB_HOST=0.0.0.0 \
    HUB_PORT=8710 \
    HUB_DATA_DIR=/data \
    HUB_PUBLIC_URL=http://localhost:8710

USER atrium
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8710

# /api/health needs no sign-in, and the Host header 127.0.0.1 is always accepted. No proxy for this local call.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python", "-c", "import os, urllib.request as u; u.build_opener(u.ProxyHandler({})).open('http://127.0.0.1:%s/api/health' % os.environ.get('HUB_PORT', '8710'), timeout=4)"]

# docker compose exec atrium atrium user list   (offline account commands, see `atrium --help`)
ENTRYPOINT ["atrium"]
CMD ["serve"]
