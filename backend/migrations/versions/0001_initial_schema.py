"""Initial 17-table NetSentinel AI schema with pgvector HNSW and PostgreSQL FTS GIN indexes."""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

from netsentinel.db.models import Base

revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "postgresql":
        op.execute("CREATE EXTENSION IF NOT EXISTS vector")
        op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")

    Base.metadata.create_all(bind=bind)

    if dialect == "postgresql":
        # Add native pgvector column & HNSW index + generated tsvector & GIN index for hybrid RAG
        op.execute("ALTER TABLE document_chunks ADD COLUMN IF NOT EXISTS embedding_vec vector(768)")
        op.execute(
            "CREATE INDEX IF NOT EXISTS ix_document_chunks_embedding_hnsw "
            "ON document_chunks USING hnsw (embedding_vec vector_cosine_ops) "
            "WITH (m = 16, ef_construction = 64)"
        )
        op.execute(
            "ALTER TABLE document_chunks ADD COLUMN IF NOT EXISTS tsv tsvector "
            "GENERATED ALWAYS AS (to_tsvector('english', coalesce(section_header, '') || ' ' || content)) STORED"
        )
        op.execute(
            "CREATE INDEX IF NOT EXISTS ix_document_chunks_tsv_gin "
            "ON document_chunks USING gin (tsv)"
        )


def downgrade() -> None:
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)
