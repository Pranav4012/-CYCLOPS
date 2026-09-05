"""Small persistence adapter for PostgreSQL with a SQLite development fallback."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from sqlalchemy import JSON, Column, Float, Integer, MetaData, String, Table, create_engine, select


class Storage:
    """Persist API state without coupling the detection engine to a database."""

    def __init__(self) -> None:
        default_path = Path(__file__).resolve().parents[1] / "cyclops.db"
        url = os.getenv("DATABASE_URL", f"sqlite:///{default_path}")
        if url.startswith("postgres://"):
            url = "postgresql+psycopg://" + url[len("postgres://"):]
        elif url.startswith("postgresql://") and "+" not in url.split("://", 1)[0]:
            url = "postgresql+psycopg://" + url[len("postgresql://"):]
        self.url = url
        connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
        self.engine = create_engine(url, future=True, pool_pre_ping=True,
                                    connect_args=connect_args)
        metadata = MetaData()
        self.jobs = Table(
            "pcap_jobs", metadata,
            Column("job_id", String(64), primary_key=True),
            Column("status", String(24), nullable=False),
            Column("progress", Integer, nullable=False),
            Column("source", String(512), nullable=False),
            Column("created_at", Float, nullable=False),
            Column("completed_at", Float),
            Column("error", String),
            Column("result", JSON),
        )
        self.records = Table(
            "detection_records", metadata,
            Column("kind", String(24), primary_key=True),
            Column("record_id", String(512), primary_key=True),
            Column("payload", JSON, nullable=False),
        )
        metadata.create_all(self.engine)

    @property
    def backend(self) -> str:
        return "postgresql" if self.url.startswith("postgresql") else "sqlite"

    def upsert_job(self, job: dict[str, Any]) -> None:
        values = {key: job.get(key) for key in
                  ("job_id", "status", "progress", "source", "created_at",
                   "completed_at", "error", "result")}
        with self.engine.begin() as connection:
            existing = connection.execute(select(self.jobs.c.job_id).where(
                self.jobs.c.job_id == job["job_id"])).first()
            if existing:
                connection.execute(self.jobs.update().where(
                    self.jobs.c.job_id == job["job_id"]).values(**values))
            else:
                connection.execute(self.jobs.insert().values(**values))

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        with self.engine.connect() as connection:
            row = connection.execute(select(self.jobs).where(
                self.jobs.c.job_id == job_id)).mappings().first()
        return dict(row) if row else None

    def load_jobs(self) -> list[dict[str, Any]]:
        with self.engine.connect() as connection:
            rows = connection.execute(select(self.jobs)).mappings().all()
        return [dict(row) for row in rows]

    def replace_records(self, kind: str, records: list[dict[str, Any]], id_key: str) -> None:
        with self.engine.begin() as connection:
            connection.execute(self.records.delete().where(self.records.c.kind == kind))
            for record in records:
                connection.execute(self.records.insert().values(
                    kind=kind, record_id=str(record[id_key]), payload=record))

    def load_records(self, kind: str) -> list[dict[str, Any]]:
        with self.engine.connect() as connection:
            rows = connection.execute(select(self.records.c.payload).where(
                self.records.c.kind == kind)).scalars().all()
        return [json.loads(json.dumps(row)) for row in rows]