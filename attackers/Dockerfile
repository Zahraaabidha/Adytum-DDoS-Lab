FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY common/ common/
COPY http_flood.py slowloris.py udp_flood.py tcp_exhaustion.py legit_load.py replay.py ./
# No CMD: the specific attack module + args are chosen per-service in docker-compose.yml
