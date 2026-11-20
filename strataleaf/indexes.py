from .catalog import record_catalog_event
from .codec import MISSING, field, loads, name, scalar_token
from .errors import Conflict, InvalidDocument, NotFound
from .mvcc import visible_rows


def refresh_document(connection, collection, key, document):
    connection.execute("DELETE FROM index_values WHERE collection=? AND key=?", (collection, key))
    if document is None:
        return
    for definition in connection.execute("SELECT * FROM index_defs WHERE collection=?", (collection,)).fetchall():
        token = scalar_token(field(document, definition["field"]))
        if token is None:
            continue
        if definition["unique_flag"]:
            existing = connection.execute("SELECT key FROM index_values WHERE collection=? AND name=? AND token=? LIMIT 1",
                                          (collection, definition["name"], token)).fetchone()
            if existing:
                raise Conflict("unique index conflict: " + definition["name"])
        connection.execute("INSERT INTO index_values VALUES (?,?,?,?)", (collection, definition["name"], token, key))


class Indexes:
    def __init__(self, store):
        self.store = store

    def create(self, collection, index_name, path, unique=False):
        name(index_name)
        field({}, path)
        if not isinstance(unique, bool):
            raise InvalidDocument("unique must be boolean")
        with self.store.atomic(writable=True) as connection:
            if not connection.execute("SELECT 1 FROM collections WHERE name=?", (collection,)).fetchone():
                raise NotFound("unknown collection")
            if connection.execute("SELECT 1 FROM index_defs WHERE collection=? AND name=?", (collection, index_name)).fetchone():
                raise Conflict("index already exists")
            connection.execute("INSERT INTO index_defs VALUES (?,?,?,?)", (collection, index_name, path, int(unique)))
            seen = set()
            for row in visible_rows(connection, collection, int(self.store.get("head"))):
                token = scalar_token(field(loads(row["body"]), path))
                if token is None:
                    continue
                if unique and token in seen:
                    raise Conflict("existing documents violate unique index")
                seen.add(token)
                connection.execute("INSERT INTO index_values VALUES (?,?,?,?)", (collection, index_name, token, row["key"]))
            self.store.set("catalog_epoch", int(self.store.get("catalog_epoch")) + 1)
            record_catalog_event(self.store, connection)
        return {"name": index_name, "field": path, "unique": unique}

    def drop(self, collection, index_name):
        with self.store.atomic(writable=True) as connection:
            changed = connection.execute("DELETE FROM index_defs WHERE collection=? AND name=?", (collection, index_name)).rowcount
            if not changed:
                raise NotFound("unknown index")
            self.store.set("catalog_epoch", int(self.store.get("catalog_epoch")) + 1)
            record_catalog_event(self.store, connection)

    def list(self, collection):
        with self.store.read() as connection:
            return [dict(row) for row in connection.execute("SELECT * FROM index_defs WHERE collection=? ORDER BY name", (collection,))]


def equality_candidates(connection, collection, path, value):
    token = scalar_token(value)
    if token is None:
        return None
    definition = connection.execute("SELECT name FROM index_defs WHERE collection=? AND field=? ORDER BY name LIMIT 1",
                                    (collection, path)).fetchone()
    if definition is None:
        return None
    keys = {row[0] for row in connection.execute("SELECT key FROM index_values WHERE collection=? AND name=? AND token=?",
                                               (collection, definition[0], token))}
    return definition[0], keys


def rebuild_current_indexes(connection):
    """Rebuild the whole current-head index projection from visible documents.

    Used by chain restore and replica catch-up: definitions must already be present.
    Raises Conflict on a unique violation rather than leaving a partial projection.
    """
    from .mvcc import visible_rows
    from .codec import loads
    head = int(connection.execute("SELECT value FROM meta WHERE key='head'").fetchone()[0])
    connection.execute("DELETE FROM index_values")
    seen = {}
    for definition in connection.execute("SELECT * FROM index_defs").fetchall():
        for row in visible_rows(connection, definition["collection"], head):
            token = scalar_token(field(loads(row["body"]), definition["field"]))
            if token is None:
                continue
            if definition["unique_flag"]:
                bucket = seen.setdefault((definition["collection"], definition["name"]), set())
                if token in bucket:
                    raise Conflict("unique index conflict: " + definition["name"])
                bucket.add(token)
            connection.execute("INSERT INTO index_values VALUES (?,?,?,?)",
                               (definition["collection"], definition["name"], token, row["key"]))
