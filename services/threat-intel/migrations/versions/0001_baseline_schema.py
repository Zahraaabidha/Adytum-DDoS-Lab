"""baseline schema

Revision ID: 0001
Revises:
Create Date: 2026-10-29 00:33:33.554454
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('cves',
    sa.Column('cve_id', sa.String(), nullable=False),
    sa.Column('description', sa.String(), nullable=True),
    sa.Column('severity', sa.String(), nullable=True),
    sa.Column('published', sa.DateTime(timezone=True), nullable=True),
    sa.Column('source', sa.String(), nullable=False),
    sa.Column('vendor_project', sa.String(), nullable=True),
    sa.Column('product', sa.String(), nullable=True),
    sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
    sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('cve_id')
    )
    op.create_table('iocs',
    sa.Column('id', sa.BigInteger(), autoincrement=True, nullable=False),
    sa.Column('ioc', sa.String(), nullable=False),
    sa.Column('ioc_type', sa.String(), nullable=False),
    sa.Column('country', sa.String(), nullable=True),
    sa.Column('lat', sa.Float(), nullable=True),
    sa.Column('lon', sa.Float(), nullable=True),
    sa.Column('asn', sa.Integer(), nullable=True),
    sa.Column('organization', sa.String(), nullable=True),
    sa.Column('city', sa.String(), nullable=True),
    sa.Column('geo_source', sa.String(), nullable=True),
    sa.Column('geo_enriched_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('threat_type', sa.String(), nullable=False),
    sa.Column('attack_family', sa.String(), nullable=True),
    sa.Column('category', sa.String(), nullable=True),
    sa.Column('confidence_score', sa.Float(), nullable=False),
    sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
    sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
    sa.Column('source_count', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('ioc', 'threat_type', name='uq_ioc_threat_type')
    )
    op.create_index(op.f('ix_iocs_asn'), 'iocs', ['asn'], unique=False)
    op.create_index(op.f('ix_iocs_country'), 'iocs', ['country'], unique=False)
    op.create_index(op.f('ix_iocs_ioc'), 'iocs', ['ioc'], unique=False)
    op.create_index(op.f('ix_iocs_last_seen'), 'iocs', ['last_seen'], unique=False)
    op.create_index(op.f('ix_iocs_threat_type'), 'iocs', ['threat_type'], unique=False)
    op.create_table('ioc_sightings',
    sa.Column('id', sa.BigInteger(), autoincrement=True, nullable=False),
    sa.Column('ioc_id', sa.BigInteger(), nullable=False),
    sa.Column('source', sa.String(), nullable=False),
    sa.Column('reported_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('category', sa.String(), nullable=True),
    sa.Column('raw', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['ioc_id'], ['iocs.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_ioc_sightings_ioc_id'), 'ioc_sightings', ['ioc_id'], unique=False)
    op.create_index(op.f('ix_ioc_sightings_source'), 'ioc_sightings', ['source'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_ioc_sightings_source'), table_name='ioc_sightings')
    op.drop_index(op.f('ix_ioc_sightings_ioc_id'), table_name='ioc_sightings')
    op.drop_table('ioc_sightings')
    op.drop_index(op.f('ix_iocs_threat_type'), table_name='iocs')
    op.drop_index(op.f('ix_iocs_last_seen'), table_name='iocs')
    op.drop_index(op.f('ix_iocs_ioc'), table_name='iocs')
    op.drop_index(op.f('ix_iocs_country'), table_name='iocs')
    op.drop_index(op.f('ix_iocs_asn'), table_name='iocs')
    op.drop_table('iocs')
    op.drop_table('cves')
