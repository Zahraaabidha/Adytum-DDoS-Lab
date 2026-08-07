"""SQLAlchemy ORM models for the normalized threat-intel schema.

Two IOC-related tables (`iocs`, `ioc_sightings`) plus a separate `cves`
table for CVE-ID-keyed feeds (CISA KEV, NVD) that have no coordinates and
don't fit the IP-centric `iocs` shape -- see `ThreatEvent`/`CveEvent` in
`schema.py` for why they're kept apart.
"""
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Float, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.common.db import Base


class Ioc(Base):
    __tablename__ = "iocs"
    __table_args__ = (UniqueConstraint("ioc", "threat_type", name="uq_ioc_threat_type"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ioc: Mapped[str] = mapped_column(String, nullable=False, index=True)
    ioc_type: Mapped[str] = mapped_column(String, nullable=False, default="ip")
    country: Mapped[str | None] = mapped_column(String, index=True)
    lat: Mapped[float | None] = mapped_column(Float)
    lon: Mapped[float | None] = mapped_column(Float)
    asn: Mapped[int | None] = mapped_column(Integer, index=True)
    organization: Mapped[str | None] = mapped_column(String)
    city: Mapped[str | None] = mapped_column(String)
    geo_source: Mapped[str | None] = mapped_column(String)  # 'geolite2' | 'fallback_api' | None (not yet enriched)
    geo_enriched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    threat_type: Mapped[str] = mapped_column(String, nullable=False, index=True)
    attack_family: Mapped[str | None] = mapped_column(String)
    category: Mapped[str | None] = mapped_column(String)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    source_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    sightings: Mapped[list["IocSighting"]] = relationship(back_populates="ioc", cascade="all, delete-orphan")


class IocSighting(Base):
    __tablename__ = "ioc_sightings"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ioc_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String, nullable=False, index=True)
    reported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    category: Mapped[str | None] = mapped_column(String)
    raw: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    ioc: Mapped["Ioc"] = relationship(back_populates="sightings")


class Cve(Base):
    __tablename__ = "cves"

    cve_id: Mapped[str] = mapped_column(String, primary_key=True)
    description: Mapped[str | None] = mapped_column(String)
    severity: Mapped[str | None] = mapped_column(String)
    published: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source: Mapped[str] = mapped_column(String, nullable=False)
    vendor_project: Mapped[str | None] = mapped_column(String)
    product: Mapped[str | None] = mapped_column(String)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
