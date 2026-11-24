"""Initial NetLog AI schema for log_entries, incidents, and anomalies.

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-11-24 00:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_initial_schema"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create core tables and indexes."""
    op.create_table(
        "log_entries",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("host", sa.String(length=255), nullable=False),
        sa.Column("source_ip", sa.String(length=64), nullable=True),
        sa.Column("service", sa.String(length=128), nullable=False),
        sa.Column("level", sa.String(length=32), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("latency_ms", sa.Float(), nullable=True),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("log_format", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_log_entries_timestamp", "log_entries", ["timestamp"])
    op.create_index("ix_log_entries_host", "log_entries", ["host"])
    op.create_index("ix_log_entries_source_ip", "log_entries", ["source_ip"])
    op.create_index("ix_log_entries_service", "log_entries", ["service"])
    op.create_index("ix_log_entries_level", "log_entries", ["level"])
    op.create_index("ix_log_entries_status_code", "log_entries", ["status_code"])
    op.create_index(
        "ix_log_entries_ts_host_service", "log_entries", ["timestamp", "host", "service"]
    )
    op.create_index("ix_log_entries_ts_status", "log_entries", ["timestamp", "status_code"])

    op.create_table(
        "incidents",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("likely_root_cause", sa.Text(), nullable=False),
        sa.Column("suggested_fix", sa.Text(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("host", sa.String(length=255), nullable=True),
        sa.Column("service", sa.String(length=128), nullable=True),
        sa.Column("window_start", sa.DateTime(), nullable=False),
        sa.Column("window_end", sa.DateTime(), nullable=False),
        sa.Column("llm_provider", sa.String(length=64), nullable=False),
        sa.Column("used_fallback", sa.Boolean(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_incidents_severity", "incidents", ["severity"])
    op.create_index("ix_incidents_status", "incidents", ["status"])
    op.create_index("ix_incidents_host", "incidents", ["host"])
    op.create_index("ix_incidents_service", "incidents", ["service"])
    op.create_index("ix_incidents_window_start", "incidents", ["window_start"])
    op.create_index("ix_incidents_window_end", "incidents", ["window_end"])

    op.create_table(
        "anomalies",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("anomaly_type", sa.String(length=64), nullable=False),
        sa.Column("detector", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("window_start", sa.DateTime(), nullable=False),
        sa.Column("window_end", sa.DateTime(), nullable=False),
        sa.Column("host", sa.String(length=255), nullable=True),
        sa.Column("service", sa.String(length=128), nullable=True),
        sa.Column("score", sa.Float(), nullable=True),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("sample_lines", sa.JSON(), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_anomalies_anomaly_type", "anomalies", ["anomaly_type"])
    op.create_index("ix_anomalies_severity", "anomalies", ["severity"])
    op.create_index("ix_anomalies_window_start", "anomalies", ["window_start"])
    op.create_index("ix_anomalies_window_end", "anomalies", ["window_end"])
    op.create_index("ix_anomalies_host", "anomalies", ["host"])
    op.create_index("ix_anomalies_service", "anomalies", ["service"])
    op.create_index("ix_anomalies_incident_id", "anomalies", ["incident_id"])
    op.create_index("ix_anomalies_severity_window", "anomalies", ["severity", "window_start"])


def downgrade() -> None:
    """Drop core tables in reverse dependency order."""
    op.drop_table("anomalies")
    op.drop_table("incidents")
    op.drop_table("log_entries")
