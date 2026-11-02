from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from app.config import settings

# Determine if we're using SQLite to configure check_same_thread
connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(
    settings.DATABASE_URL, connect_args=connect_args
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def ensure_schema_compatibility():
    """Safely adds missing columns to existing tables for backwards-compatible SQLite/Postgres schemas."""
    try:
        with engine.begin() as conn:
            if settings.DATABASE_URL.startswith("sqlite"):
                # 1. Check alerts table columns
                result = conn.execute(text("PRAGMA table_info(alerts)"))
                existing_cols = {row[1] for row in result.fetchall()}
                alerts_column_defs = [
                    ("rule_id", "VARCHAR"),
                    ("alert_code", "VARCHAR"),
                    ("source_ip", "VARCHAR"),
                    ("username", "VARCHAR"),
                    ("evidence", "TEXT"),
                    ("matched_event_ids", "TEXT"),
                    ("is_demo", "BOOLEAN DEFAULT 0")
                ]
                for col_name, col_type in alerts_column_defs:
                    if col_name not in existing_cols:
                        conn.execute(text(f"ALTER TABLE alerts ADD COLUMN {col_name} {col_type}"))

                # 2. Check security_alerts table columns
                sec_result = conn.execute(text("PRAGMA table_info(security_alerts)"))
                existing_sec_cols = {row[1] for row in sec_result.fetchall()}
                sec_column_defs = [
                    ("occurrence_count", "INTEGER DEFAULT 1"),
                    ("is_duplicate", "BOOLEAN DEFAULT 0"),
                    ("dedup_key", "VARCHAR"),
                    ("first_seen_at", "DATETIME"),
                    ("last_seen_at", "DATETIME"),
                    ("destination_ip", "VARCHAR"),
                    ("correlation_id", "VARCHAR"),
                    ("risk_score", "FLOAT DEFAULT 0.0"),
                    ("risk_factors", "TEXT"),
                    ("threat_intel", "TEXT"),
                    ("ai_analysis", "TEXT"),
                    ("priority", "VARCHAR DEFAULT 'P3'"),
                    ("notes", "TEXT"),
                    ("audit_trail", "TEXT")
                ]
                for col_name, col_type in sec_column_defs:
                    if col_name not in existing_sec_cols:
                        conn.execute(text(f"ALTER TABLE security_alerts ADD COLUMN {col_name} {col_type}"))

                # 3. Check security_events table columns
                sec_evt_result = conn.execute(text("PRAGMA table_info(security_events)"))
                existing_sec_evt_cols = {row[1] for row in sec_evt_result.fetchall()}
                sec_evt_column_defs = [
                    ("category", "VARCHAR DEFAULT 'Authentication'"),
                    ("detection_status", "VARCHAR DEFAULT 'Normal'"),
                    ("matched_rule_id", "VARCHAR"),
                    ("risk_score", "FLOAT DEFAULT 0.0")
                ]
                for col_name, col_type in sec_evt_column_defs:
                    if col_name not in existing_sec_evt_cols:
                        conn.execute(text(f"ALTER TABLE security_events ADD COLUMN {col_name} {col_type}"))
    except Exception as e:
        # Table might not exist yet, which create_all will handle
        pass

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

