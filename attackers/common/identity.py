"""Synthetic attacker identity tagging.

IMPORTANT: this module never touches real routing, real source IPs, or real
geolocation lookups. It only generates a fake label (a made-up IP-looking
string + a coordinate drawn from a static pool of city locations) that is
attached to simulation events purely so the globe visualization has
something to draw. It has no effect whatsoever on the packets actually sent
on the wire, which always originate from the attacker container's real
internal Docker IP on the isolated attacker_net/target_net.
"""
import random
from dataclasses import dataclass

# Static pool of (city, lat, lon) used only for the synthetic globe visualization.
_FAKE_LOCATIONS = [
    ("Sao Paulo, BR", -23.5505, -46.6333),
    ("Lagos, NG", 6.5244, 3.3792),
    ("Jakarta, ID", -6.2088, 106.8456),
    ("Moscow, RU", 55.7558, 37.6173),
    ("Mumbai, IN", 19.0760, 72.8777),
    ("Cairo, EG", 30.0444, 31.2357),
    ("Bogota, CO", 4.7110, -74.0721),
    ("Manila, PH", 14.5995, 120.9842),
    ("Tehran, IR", 35.6892, 51.3890),
    ("Hanoi, VN", 21.0278, 105.8342),
    ("Bucharest, RO", 44.4268, 26.1025),
    ("Karachi, PK", 24.8607, 67.0011),
]


@dataclass(frozen=True)
class FakeIdentity:
    fake_ip: str
    city: str
    lat: float
    lon: float


def _fake_ip() -> str:
    """A syntactically IP-shaped string in the documentation/example ranges
    (RFC 5737 / RFC 3849 style blocks are avoided here in favor of clearly
    fictitious high octets) -- never a real routable address, and never used
    for actual networking, only as a display label."""
    return f"203.0.113.{random.randint(1, 254)}"


def random_fake_identity() -> FakeIdentity:
    city, lat, lon = random.choice(_FAKE_LOCATIONS)

    def jitter(v: float) -> float:
        # jitter so multiple simulated attackers from the same "city" don't overlap exactly
        return v + random.uniform(-0.5, 0.5)

    return FakeIdentity(fake_ip=_fake_ip(), city=city, lat=jitter(lat), lon=jitter(lon))
