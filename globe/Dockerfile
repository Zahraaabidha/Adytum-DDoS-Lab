FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi==0.115.0 uvicorn[standard]==0.30.6

# Docker CLI + compose plugin (static binaries, no apt docker.io package) so
# this container can drive sibling containers over the mounted docker.sock --
# used only by the sandbox attack start/stop controls in server.py. Nothing
# else in this container needs a full Docker Engine install.
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && \
    curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-29.6.1.tgz \
      | tar xz --strip-components=1 -C /usr/local/bin docker/docker && \
    mkdir -p /usr/local/lib/docker/cli-plugins && \
    curl -fsSL -o /usr/local/lib/docker/cli-plugins/docker-compose \
      https://github.com/docker/compose/releases/download/v5.3.1/docker-compose-linux-x86_64 && \
    chmod +x /usr/local/lib/docker/cli-plugins/docker-compose && \
    apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

COPY server.py index.html app.js ./
COPY vendor/ ./vendor/
EXPOSE 8090
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8090"]
