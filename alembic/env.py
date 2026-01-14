from logging.config import fileConfig

from sqlalchemy import engine_from_config
from sqlalchemy import pool

from alembic import context

import os
import sys

# Add the src directory to the path so we can import faramesh modules
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from faramesh.server.settings import get_settings

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Determine database URL (prefer environment variables to avoid cached settings)
settings = get_settings()
db_backend = os.getenv("FARA_DB_BACKEND", settings.db_backend).lower()
sqlite_path = os.getenv("FARA_SQLITE_PATH", settings.sqlite_path)
postgres_dsn = os.getenv("FARA_POSTGRES_DSN", settings.postgres_dsn)

if db_backend == "postgres":
    database_url = postgres_dsn
else:
    database_url = f"sqlite:///{sqlite_path}"

# Override sqlalchemy.url with our database URL
config.set_main_option("sqlalchemy.url", database_url)

target_metadata = None


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
