"""App-side Postgres column encryption (backlog #11).

Driver-agnostic: produce the DDL for a table, then call `seal_row` before INSERT/UPDATE and
`open_row` after SELECT. Each encrypted column becomes `<col>_ct bytea` (a v2 envelope bound
to tenant/table/row id/column) plus an optional `<col>_bi bytea` blind index for equality
lookups. Postgres only ever sees ciphertext; keys stay in the app (zero-knowledge).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .envelope import VERSION_V2, Keyring, RecordContext, blind_index, decrypt, encrypt

_IDENT = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


def _ident(name: str) -> str:
    if not _IDENT.match(name):
        raise ValueError(f"unsafe SQL identifier: {name!r}")
    return name


@dataclass
class EncryptedTable:
    table: str
    id_column: str
    columns: list[str]
    indexed: set[str] = field(default_factory=set)
    purpose: str = "pg-column"
    schema_version: int = 1

    def __post_init__(self) -> None:
        for n in [self.table, self.id_column, *self.columns]:
            _ident(n)
        if not self.indexed <= set(self.columns):
            raise ValueError("indexed columns must be encrypted columns")

    def ddl(self) -> str:
        """`ALTER TABLE` adding the ciphertext and blind-index columns (idempotent)."""
        out = []
        for c in self.columns:
            out.append(f"ALTER TABLE {self.table} ADD COLUMN IF NOT EXISTS {c}_ct bytea;")
            if c in self.indexed:
                out.append(f"ALTER TABLE {self.table} ADD COLUMN IF NOT EXISTS {c}_bi bytea;")
                out.append(f"CREATE INDEX IF NOT EXISTS {self.table}_{c}_bi_idx ON {self.table} ({c}_bi);")
        return "\n".join(out)

    def _ctx(self, tenant: str, row_id: str, col: str) -> RecordContext:
        return RecordContext(tenant, self.purpose, self.table, str(row_id), col, self.schema_version)

    def seal_row(self, kr: Keyring, index_key: bytes, tenant: str, row: dict) -> dict:
        """Return a dict of column -> value to write. Plaintext columns are dropped."""
        rid = str(row[self.id_column])
        out = {k: v for k, v in row.items() if k not in self.columns}
        for c in self.columns:
            if row.get(c) is None:
                out[f"{c}_ct"] = None
                if c in self.indexed:
                    out[f"{c}_bi"] = None
                continue
            val = str(row[c])
            out[f"{c}_ct"] = encrypt(kr, self._ctx(tenant, rid, c), val.encode())
            if c in self.indexed:
                out[f"{c}_bi"] = blind_index(index_key, tenant, f"{self.table}.{c}", val)
        return out

    def open_row(self, kr: Keyring, tenant: str, row: dict) -> dict:
        rid = str(row[self.id_column])
        out = {k: v for k, v in row.items() if not k.endswith(("_ct", "_bi"))}
        for c in self.columns:
            blob = row.get(f"{c}_ct")
            out[c] = None if blob is None else decrypt(kr, self._ctx(tenant, rid, c), bytes(blob), min_version=VERSION_V2).decode()
        return out

    def lookup(self, index_key: bytes, tenant: str, col: str, value: str) -> tuple[str, tuple]:
        """Parameterized equality query on a blind index (psycopg/asyncpg-style %s placeholder)."""
        if col not in self.indexed:
            raise ValueError(f"{col} has no blind index")
        bi = blind_index(index_key, tenant, f"{self.table}.{col}", value)
        return f"SELECT * FROM {self.table} WHERE {col}_bi = %s", (bi,)
