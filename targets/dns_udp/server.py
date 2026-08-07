"""SENTINEL LAB target: a DNS-like UDP service with Prometheus metrics.

Not a real DNS resolver -- it accepts arbitrary UDP datagrams shaped like
simple query packets and replies with a small canned response, purely to
give the lab a UDP-flood target with realistic connectionless semantics.
"""
import asyncio
import os

from prometheus_client import Counter, Gauge, start_http_server

INSTANCE_ID = os.environ.get("HOSTNAME", "udp-unknown")
UDP_PORT = int(os.environ.get("UDP_PORT", "5300"))
METRICS_PORT = int(os.environ.get("METRICS_PORT", "9200"))

PACKETS_TOTAL = Counter("target_udp_packets_total", "Total UDP packets received", ["instance"])
BYTES_TOTAL = Counter("target_udp_bytes_received_total", "Total UDP bytes received", ["instance"])
RESPONSES_TOTAL = Counter("target_udp_responses_total", "Total UDP responses sent", ["instance"])
INFLIGHT = Gauge("target_udp_inflight_datagrams", "Datagrams currently being processed", ["instance"])


class DNSLikeProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        PACKETS_TOTAL.labels(instance=INSTANCE_ID).inc()
        BYTES_TOTAL.labels(instance=INSTANCE_ID).inc(len(data))
        INFLIGHT.labels(instance=INSTANCE_ID).inc()
        try:
            # Echo a short canned "answer" record back to sender.
            reply = data[:2] + b"\x81\x80" + b"\x00\x01" * 4 if len(data) >= 2 else b"\x00\x00"
            self.transport.sendto(reply, addr)
            RESPONSES_TOTAL.labels(instance=INSTANCE_ID).inc()
        finally:
            INFLIGHT.labels(instance=INSTANCE_ID).dec()


async def main():
    start_http_server(METRICS_PORT)
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        DNSLikeProtocol, local_addr=("0.0.0.0", UDP_PORT)
    )
    print(f"[{INSTANCE_ID}] UDP DNS-like target listening on :{UDP_PORT}, metrics on :{METRICS_PORT}")
    try:
        await asyncio.Event().wait()
    finally:
        transport.close()


if __name__ == "__main__":
    asyncio.run(main())
