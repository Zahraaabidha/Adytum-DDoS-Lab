"""SENTINEL LAB target: a generic TCP echo-style service with Prometheus metrics.

Used to demonstrate TCP connection-exhaustion style attacks. Exposes a
Prometheus metrics endpoint on a separate small HTTP port.
"""
import asyncio
import os
import time

from prometheus_client import Counter, Gauge, Histogram, start_http_server

INSTANCE_ID = os.environ.get("HOSTNAME", "tcp-unknown")
TCP_PORT = int(os.environ.get("TCP_PORT", "9000"))
METRICS_PORT = int(os.environ.get("METRICS_PORT", "9100"))

CONNECTIONS_TOTAL = Counter("target_tcp_connections_total", "Total TCP connections accepted", ["instance"])
ACTIVE_CONNECTIONS = Gauge("target_tcp_active_connections", "Currently open TCP connections", ["instance"])
CONNECTION_DURATION = Histogram("target_tcp_connection_duration_seconds", "TCP connection lifetime", ["instance"])
BYTES_RECEIVED = Counter("target_tcp_bytes_received_total", "Total bytes received", ["instance"])


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    CONNECTIONS_TOTAL.labels(instance=INSTANCE_ID).inc()
    ACTIVE_CONNECTIONS.labels(instance=INSTANCE_ID).inc()
    start = time.perf_counter()
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break
            BYTES_RECEIVED.labels(instance=INSTANCE_ID).inc(len(data))
            writer.write(data)  # echo back
            await writer.drain()
    except (ConnectionResetError, asyncio.IncompleteReadError):
        pass
    finally:
        ACTIVE_CONNECTIONS.labels(instance=INSTANCE_ID).dec()
        CONNECTION_DURATION.labels(instance=INSTANCE_ID).observe(time.perf_counter() - start)
        writer.close()


async def main():
    start_http_server(METRICS_PORT)
    server = await asyncio.start_server(handle_client, "0.0.0.0", TCP_PORT)
    print(f"[{INSTANCE_ID}] TCP echo target listening on :{TCP_PORT}, metrics on :{METRICS_PORT}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
