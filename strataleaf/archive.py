import hashlib
import hmac
import os
import sqlite3
import tempfile
import secrets
import uuid
from pathlib import Path
from .codec import digest, dumps, loads
from .errors import Conflict, DatabaseError, InvalidDocument, ChainError
from .mvcc import visible_rows


def file_digest(path):
    result = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def inspect_archive(path):
    connection = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)
    try:
        result = connection.execute("PRAGMA integrity_check").fetchone()[0]
        values = dict(connection.execute("SELECT key,value FROM meta"))
        required = {"head", "floor", "format", "database_id", "cursor_secret", "mode", "upstream"}
        if result != "ok" or not required.issubset(values) or values["format"] != "1":
            raise DatabaseError("archive is not a supported intact database")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise DatabaseError("archive has broken references")
        return {"revision": int(values["head"]), "floor": int(values["floor"]),
                "database_id": values["database_id"], "sha256": file_digest(path)}
    except (sqlite3.DatabaseError, KeyError, ValueError) as exc:
        raise DatabaseError("invalid database archive") from exc
    finally:
        connection.close()


def _resolve(path):
    return Path(path).resolve()


def _discard(path):
    """Remove an unpublished temporary database and any SQLite sidecars."""
    for suffix in ("", "-wal", "-shm", "-journal"):
        Path(str(path) + suffix).unlink(missing_ok=True)


def _catalog_at(connection, revision, base_state=None, base_epoch=0):
    """Materialize the catalog state visible at document ``revision``.

    Catalog epochs advance independently of document revisions. Each event stores a
    complete catalog state and the ``(rev, epoch)`` at which it was installed; since
    revisions and epochs both advance monotonically, the highest epoch with
    ``rev <= revision`` is the latest eligible state. ``base_state`` is the catalog
    carried by the baseline copy itself, used when no event is newer than the
    baseline's own epoch (for example a baseline written before catalog history).
    """
    row = connection.execute("SELECT collections,indexes,epoch FROM catalog_events "
                             "WHERE rev<=? ORDER BY epoch DESC LIMIT 1", (revision,)).fetchone()
    if row is None or (base_state is not None and int(row[2]) <= base_epoch):
        return (base_state if base_state is not None
                else {"collections": [], "indexes": []}, base_epoch)
    return {"collections": loads(row[0]), "indexes": loads(row[1])}, int(row[2])


def _baseline_catalog(connection):
    """Read the catalog state and epoch carried by a copied baseline snapshot."""
    from .catalog import catalog_state
    row = connection.execute("SELECT value FROM meta WHERE key='catalog_epoch'").fetchone()
    return catalog_state(connection), int(row[0]) if row else 0


class Archives:
    def __init__(self, store):
        self.store = store

    def backup(self, destination):
        destination = Path(destination).resolve()
        if destination.exists():
            raise Conflict("backup destination already exists")
        destination.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".strataleaf-", dir=destination.parent)
        os.close(fd)
        try:
            with self.store.lock:
                if self.store.closed:
                    raise DatabaseError("database handle is closed")
                target = sqlite3.connect(temporary)
                try:
                    self.store.connection.backup(target)
                finally:
                    target.close()
            receipt = inspect_archive(temporary)
            os.link(temporary, destination)
            return {**receipt, "path": str(destination)}
        except FileExistsError as exc:
            raise Conflict("backup destination appeared concurrently") from exc
        finally:
            _discard(temporary)

    @staticmethod
    def restore(source, destination, expected_sha256=None, follower=False):
        source, destination = Path(source).resolve(), Path(destination).resolve()
        receipt = inspect_archive(source)
        if expected_sha256 is not None and expected_sha256 != receipt["sha256"]:
            raise DatabaseError("archive checksum mismatch")
        if destination.exists():
            raise Conflict("restore requires an unused destination")
        destination.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".strataleaf-restore-", dir=destination.parent)
        os.close(fd)
        original = None
        target = None
        try:
            original = sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)
            target = sqlite3.connect(temporary)
            original.backup(target)
            target.execute("UPDATE meta SET value=? WHERE key='mode'", ("replica" if follower else "primary",))
            target.execute("UPDATE meta SET value=? WHERE key='upstream'", (receipt["database_id"] if follower else "",))
            if not follower:
                target.execute("UPDATE meta SET value=? WHERE key='database_id'", (str(uuid.uuid4()),))
                target.execute("UPDATE meta SET value=? WHERE key='cursor_secret'", (secrets.token_hex(32),))
            target.execute("DELETE FROM pins")
            target.execute("DELETE FROM consumers")
            target.execute("DELETE FROM chain_state")
            target.execute("DELETE FROM chain_holds")
            target.commit()
            target.close()
            target = None
            os.link(temporary, destination)
        except FileExistsError as exc:
            raise Conflict("restore destination appeared concurrently") from exc
        finally:
            if original:
                original.close()
            if target:
                target.close()
            _discard(temporary)
        return {**receipt, "path": str(destination), "mode": "replica" if follower else "primary"}

class BackupChain:
    """Incremental backup chain rooted at one published full baseline.

    A segment is a self-describing JSON envelope ``{"body": ..., "sha256": ...}``.
    Its identity is ``(chain_id, seq)``; its dependencies are
    ``(base_sha256, baseline_revision, from_rev, prev_sha256, prev_epoch)``. Each body
    carries the logical operation stream of every commit in its range — live revisions,
    explicit tombstone revisions (``document: null``) and expiry facts — plus every
    catalog event (collection schemas and index definitions) recorded in that range.
    Replaying a segment prefix therefore reproduces deletions, schema evolutions and
    index changes, not only the current live documents.

    A published segment records a ``chain_holds`` floor at its ``from_rev``.
    ``Retention.compact`` stops at that floor, so reclamation never strands a segment
    that has already been produced. Cadence is decided by the caller: any number of
    commits may live between segments, and empty segments are legal (they still carry
    the catalog epoch).

    ``verify`` checks a single envelope (checksum, chain identity, sequence, baseline
    dependency, predecessor digest/epoch, contiguous revision range). ``plan`` checks a
    whole ordered prefix and resolves the reachable target revision. ``restore``
    validates before touching the destination, assembles the result in a temporary
    file and links it into place only after a logical and index self-check. A missing
    segment, wrong order or failed checksum never mutates the baseline and never
    publishes a partial destination.
    """

    FORMAT = 1

    def __init__(self, store):
        self.store = store

    # -- production -------------------------------------------------------
    def begin(self, baseline):
        """Register a chain identity for a baseline published by Archives.backup."""
        baseline = _resolve(baseline)
        receipt = inspect_archive(baseline)
        with self.store.atomic(writable=True) as connection:
            head, floor = int(self.store.get("head")), int(self.store.get("floor"))
            if head != receipt["revision"]:
                raise ChainError("baseline revision does not match current head")
            if floor > receipt["revision"]:
                raise ChainError("baseline revision is older than the retained floor")
            epoch = self._baseline_epoch(baseline)
            chain_id = str(uuid.uuid4())
            connection.execute("INSERT INTO chain_state VALUES (?,?,?,?,?,?,?,?)",
                               (chain_id, receipt["sha256"], receipt["revision"], epoch,
                                0, receipt["revision"], "", epoch))
            # Hold the floor at the baseline revision: the producer must still be able to
            # read commits after it when the first segment is appended.
            connection.execute("INSERT INTO chain_holds VALUES (?,?)",
                               (chain_id, receipt["revision"]))
        return {"chain_id": chain_id, "baseline_sha256": receipt["sha256"],
                "baseline_revision": receipt["revision"], "baseline_epoch": epoch,
                "head": head}

    def status(self, chain_id):
        with self.store.read() as connection:
            state = connection.execute("SELECT * FROM chain_state WHERE chain_id=?",
                                       (chain_id,)).fetchone()
            hold = connection.execute("SELECT rev FROM chain_holds WHERE chain_id=?",
                                      (chain_id,)).fetchone()
            if state is None:
                raise ChainError("unknown backup chain")
            return {"chain_id": state["chain_id"], "baseline_sha256": state["baseline_sha256"],
                    "baseline_revision": int(state["baseline_rev"]),
                    "baseline_epoch": int(state["baseline_epoch"]), "seq": int(state["seq"]),
                    "through": int(state["through"]), "catalog_epoch": int(state["catalog_epoch"]),
                    "hold": int(hold[0]) if hold else None}

    def append(self, chain_id):
        """Publish one segment covering ``(through, head]`` from a single IMMEDIATE view."""
        with self.store.atomic(writable=True) as connection:
            state = connection.execute("SELECT * FROM chain_state WHERE chain_id=?",
                                       (chain_id,)).fetchone()
            if state is None:
                raise ChainError("unknown backup chain")
            head, floor = int(self.store.get("head")), int(self.store.get("floor"))
            from_rev, through = int(state["through"]), head
            if from_rev < floor:
                raise ChainError("history was reclaimed past the previous segment; take a new baseline")
            commits = [loads(row[0]) for row in
                       connection.execute("SELECT payload FROM commits WHERE rev>? AND rev<=? "
                                          "ORDER BY rev", (from_rev, through))]
            if [c["revision"] for c in commits] != list(range(from_rev + 1, through + 1)):
                raise ChainError("commit log does not cover the requested segment range")
            events = [{"epoch": int(row["epoch"]), "rev": int(row["rev"]),
                       "collections": loads(row["collections"]),
                       "indexes": loads(row["indexes"])}
                      for row in connection.execute(
                          "SELECT * FROM catalog_events WHERE epoch>? AND epoch<=? ORDER BY epoch",
                          (int(state["catalog_epoch"]), int(self.store.get("catalog_epoch"))))]
            body = {"format": self.FORMAT, "chain_id": chain_id, "seq": int(state["seq"]) + 1,
                    "base_sha256": state["baseline_sha256"],
                    "baseline_revision": int(state["baseline_rev"]),
                    "baseline_epoch": int(state["baseline_epoch"]),
                    "from_rev": from_rev, "through": through,
                    "prev_sha256": state["body_sha256"],
                    "prev_epoch": int(state["catalog_epoch"]),
                    "catalog_epoch": int(self.store.get("catalog_epoch")),
                    "commits": commits, "catalog_events": events}
            body_sha = digest(body)
            connection.execute("UPDATE chain_state SET seq=?,through=?,body_sha256=?,catalog_epoch=? "
                               "WHERE chain_id=?",
                               (body["seq"], through, body_sha, body["catalog_epoch"], chain_id))
            # Compaction may advance to ``through``: later appends only need commits
            # after it, and already published segments are self-contained.
            connection.execute("UPDATE chain_holds SET rev=? WHERE chain_id=? AND rev<?",
                               (through, chain_id, through))
            enforced = connection.execute("SELECT rev FROM chain_holds WHERE chain_id=?",
                                          (chain_id,)).fetchone()[0]
        return {"envelope": {"body": body, "sha256": body_sha},
                "identity": {"chain_id": chain_id, "seq": body["seq"],
                             "base_sha256": body["base_sha256"],
                             "baseline_revision": body["baseline_revision"]},
                "dependency": {"from_rev": from_rev, "prev_sha256": body["prev_sha256"],
                               "prev_epoch": body["prev_epoch"]},
                "range": {"from": from_rev, "through": through},
                "catalog_events": len(events), "commits": len(commits),
                "retention_hold": int(enforced), "sha256": body_sha}

    def discard(self, chain_id):
        """Retire a chain identity and its retention hold.

        Use when a baseline is replaced or when a registered chain will not receive
        further segments; otherwise its hold keeps compaction from advancing.
        Already published segments remain self-contained and restorable.
        """
        with self.store.atomic(writable=True) as connection:
            state = connection.execute("SELECT * FROM chain_state WHERE chain_id=?",
                                       (chain_id,)).fetchone()
            if state is None:
                raise ChainError("unknown backup chain")
            connection.execute("DELETE FROM chain_holds WHERE chain_id=?", (chain_id,))
            connection.execute("DELETE FROM chain_state WHERE chain_id=?", (chain_id,))
            return {"chain_id": chain_id, "released_hold": int(state["through"])}

    # -- identity and dependency validation --------------------------------
    @staticmethod
    def _body_of(envelope):
        if not isinstance(envelope, dict) or set(envelope) != {"body", "sha256"}:
            raise ChainError("segment envelope must contain exactly body and sha256")
        return envelope["body"], envelope["sha256"]

    @classmethod
    def verify(cls, envelope, *, chain_id, seq, expected_from, baseline_sha256=None,
               baseline_revision=None, baseline_epoch=None, prev_sha256=None, prev_epoch=None):
        """Validate one segment's identity, dependency, ordering and checksum."""
        body, sha = cls._body_of(envelope)
        try:
            calculated = digest(body)
        except (TypeError, ValueError) as exc:
            raise ChainError("segment body is not representable JSON") from exc
        if not isinstance(sha, str) or not hmac.compare_digest(sha, calculated):
            raise ChainError("segment checksum mismatch")
        if body.get("format") != cls.FORMAT:
            raise ChainError("unsupported segment format")
        if body.get("chain_id") != chain_id:
            raise ChainError("segment belongs to a different chain identity")
        if body.get("seq") != seq:
            raise ChainError(f"segment sequence out of order: expected {seq}, found {body.get('seq')!r}")
        if baseline_sha256 is not None and body.get("base_sha256") != baseline_sha256:
            raise ChainError("segment baseline dependency mismatch")
        if baseline_revision is not None and body.get("baseline_revision") != baseline_revision:
            raise ChainError("segment baseline revision mismatch")
        if baseline_epoch is not None and body.get("baseline_epoch") != baseline_epoch:
            raise ChainError("segment baseline catalog epoch mismatch")
        if body.get("from_rev") != expected_from:
            raise ChainError("segment range does not continue the chain")
        through = body.get("through")
        if isinstance(through, bool) or not isinstance(through, int) or through < expected_from:
            raise ChainError("segment range is inverted")
        if prev_sha256 is not None and body.get("prev_sha256") != prev_sha256:
            raise ChainError("segment predecessor digest mismatch")
        if prev_epoch is not None and body.get("prev_epoch") != prev_epoch:
            raise ChainError("segment predecessor catalog epoch mismatch")
        for key in ("seq", "from_rev", "through", "baseline_revision", "prev_epoch", "catalog_epoch"):
            if isinstance(body.get(key), bool) or not isinstance(body.get(key), int):
                raise ChainError("segment has a non-integer identity field: " + key)
        if body["prev_epoch"] > body["catalog_epoch"]:
            raise ChainError("segment catalog epoch moves backwards")
        commits, events = body.get("commits"), body.get("catalog_events")
        if not isinstance(commits, list) or not isinstance(events, list):
            raise ChainError("segment lacks commit or catalog history")
        if [c.get("revision") for c in commits] != list(range(expected_from + 1, through + 1)):
            raise ChainError("segment commit revisions are reordered or gapped")
        previous = body["prev_epoch"]
        for event in events:
            if (not isinstance(event, dict) or not isinstance(event.get("rev"), int)
                    or isinstance(event.get("rev"), bool)
                    or not expected_from <= event["rev"] <= through
                    or not isinstance(event.get("collections"), list)
                    or not isinstance(event.get("indexes"), list)):
                raise ChainError("segment catalog events are malformed or out of range")
            epoch = event.get("epoch")
            if (isinstance(epoch, bool) or not isinstance(epoch, int)
                    or not previous < epoch <= body["catalog_epoch"]):
                raise ChainError("segment catalog epochs are misordered or outside the segment")
            previous = epoch
        if events and events[-1]["epoch"] != body["catalog_epoch"]:
            raise ChainError("segment does not carry its declared catalog epoch")
        return body

    # -- restore planning --------------------------------------------------
    @classmethod
    def plan(cls, baseline, segments, through=None):
        """Validate a chain prefix without restoring and report the reachable target."""
        baseline = _resolve(baseline)
        base_receipt = inspect_archive(baseline)
        if not isinstance(segments, (list, tuple)) or not segments:
            raise ChainError("chain restore requires at least one segment")
        first, _ = cls._body_of(segments[0])
        chain_id = first.get("chain_id")
        base_epoch = cls._baseline_epoch(baseline)
        current, previous_sha, previous_epoch = base_receipt["revision"], "", base_epoch
        for offset, envelope in enumerate(segments):
            body = cls.verify(envelope, chain_id=chain_id, seq=offset + 1,
                               expected_from=current, baseline_sha256=base_receipt["sha256"],
                               baseline_revision=base_receipt["revision"],
                               baseline_epoch=base_epoch,
                               prev_sha256=previous_sha, prev_epoch=previous_epoch)
            previous_sha, current, previous_epoch = (envelope["sha256"], body["through"],
                                                    body["catalog_epoch"])
        target = current if through is None else through
        if isinstance(target, bool) or not isinstance(target, int) or not (
                current >= target >= base_receipt["revision"]):
            raise ChainError("requested revision is not reachable in the supplied prefix")
        return {"chain_id": chain_id, "segments": len(segments),
                "baseline_revision": base_receipt["revision"], "through": current,
                "target": target, "catalog_epoch": previous_epoch}

    @staticmethod
    def _baseline_epoch(baseline):
        """Read the catalog epoch actually stored in the baseline archive."""
        connection = sqlite3.connect(Path(baseline).resolve().as_uri() + "?mode=ro", uri=True)
        try:
            row = connection.execute("SELECT value FROM meta WHERE key='catalog_epoch'").fetchone()
            if row is None:
                raise ChainError("baseline has no catalog epoch")
            return int(row[0])
        finally:
            connection.close()

    # -- restoration -------------------------------------------------------
    @classmethod
    def restore(cls, baseline, segments, destination, through=None, expected_sha256=None,
                follower=False):
        """Restore ``through`` from a baseline plus ordered segment envelopes."""
        baseline, destination = _resolve(baseline), _resolve(destination)
        if expected_sha256 is not None and file_digest(baseline) != expected_sha256:
            raise ChainError("baseline checksum mismatch")
        if destination.exists():
            raise Conflict("restore requires an unused destination")
        plan = cls.plan(baseline, segments, through)
        base_receipt = inspect_archive(baseline)
        target = plan["target"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".strataleaf-chain-", dir=destination.parent)
        os.close(fd)
        source = connection = None
        try:
            source = sqlite3.connect(baseline.as_uri() + "?mode=ro", uri=True)
            connection = sqlite3.connect(temporary)
            connection.row_factory = sqlite3.Row
            # Collections are rebuilt after replay; validate references at the end instead.
            connection.execute("PRAGMA foreign_keys=OFF")
            source.backup(connection)
            base_state, base_epoch = _baseline_catalog(connection)
            cls._replay(connection, segments, base_receipt["revision"], target)
            state, epoch = _catalog_at(connection, target, base_state, base_epoch)
            cls._install_catalog(connection, state, epoch)
            connection.execute("UPDATE meta SET value=? WHERE key='mode'",
                               ("replica" if follower else "primary",))
            connection.execute("UPDATE meta SET value=? WHERE key='upstream'",
                               (base_receipt["database_id"] if follower else "",))
            if not follower:
                connection.execute("UPDATE meta SET value=? WHERE key='database_id'",
                                   (str(uuid.uuid4()),))
                connection.execute("UPDATE meta SET value=? WHERE key='cursor_secret'",
                                   (secrets.token_hex(32),))
            connection.execute("DELETE FROM pins")
            connection.execute("DELETE FROM consumers")
            connection.execute("DELETE FROM chain_state")
            connection.execute("DELETE FROM chain_holds")
            connection.commit()
            problems = cls._post_check(connection)
            if problems:
                raise ChainError("restored chain failed verification: " + "; ".join(problems))
            connection.close()
            connection = None
            os.link(temporary, destination)
        except FileExistsError as exc:
            raise Conflict("restore destination appeared concurrently") from exc
        finally:
            if source:
                source.close()
            if connection:
                connection.close()
            _discard(temporary)
        return {**base_receipt, "path": str(destination),
                "mode": "replica" if follower else "primary", "revision": target,
                "chain_id": plan["chain_id"], "segments": plan["segments"]}

    @staticmethod
    def _replay(connection, segments, baseline_revision, target):
        """Replay commit operation streams, including tombstones, up to ``target``."""
        head = int(connection.execute("SELECT value FROM meta WHERE key='head'").fetchone()[0])
        if head != baseline_revision:
            raise ChainError("baseline read version changed during restore")
        events = []
        for envelope in segments:
            body = envelope["body"]
            events.extend(body["catalog_events"])
            for commit in body["commits"]:
                revision = commit["revision"]
                if revision > target:
                    break
                if revision != head + 1:
                    raise ChainError("segment commits cannot be replayed in order")
                for operation in commit["operations"]:
                    connection.execute("INSERT INTO versions VALUES (?,?,?,?,?)",
                                       (operation["collection"], operation["key"], revision,
                                        None if operation["document"] is None
                                        else dumps(operation["document"]),
                                        operation["expires_at"]))
                connection.execute("INSERT INTO commits(rev,payload) VALUES (?,?)",
                                   (revision, dumps(commit)))
                head = revision
            if head >= target:
                break
        if head != target:
            raise ChainError("supplied segments do not reach the requested revision")
        for event in events:
            connection.execute("INSERT OR REPLACE INTO catalog_events VALUES (?,?,?,?)",
                               (event["epoch"], event["rev"],
                                dumps(event["collections"]), dumps(event["indexes"])))
        connection.execute("DELETE FROM catalog_events WHERE rev>?", (target,))
        connection.execute("UPDATE meta SET value=? WHERE key='head'", (str(head),))

    @staticmethod
    def _install_catalog(connection, state, epoch):
        """Rebuild collections, index definitions and current values for the restored head."""
        from .indexes import rebuild_current_indexes
        connection.execute("DELETE FROM index_values")
        connection.execute("DELETE FROM index_defs")
        connection.execute("DELETE FROM collections")
        for definition in state["collections"]:
            connection.execute("INSERT INTO collections VALUES (?,?,?)",
                               (definition["name"], dumps(definition["schema"]),
                                int(definition["generation"])))
        for definition in state["indexes"]:
            connection.execute("INSERT INTO index_defs VALUES (?,?,?,?)",
                               (definition["collection"], definition["name"],
                                definition["field"], int(definition["unique_flag"])))
        rebuild_current_indexes(connection)
        connection.execute("UPDATE meta SET value=? WHERE key='catalog_epoch'", (str(epoch),))

    @staticmethod
    def _post_check(connection):
        from .codec import field, scalar_token
        problems = []
        if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            problems.append("SQLite integrity failure")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            problems.append("broken references")
        head = int(connection.execute("SELECT value FROM meta WHERE key='head'").fetchone()[0])
        floor = int(connection.execute("SELECT value FROM meta WHERE key='floor'").fetchone()[0])
        revisions = [row[0] for row in
                     connection.execute("SELECT rev FROM commits WHERE rev>? ORDER BY rev", (floor,))]
        if revisions != list(range(floor + 1, head + 1)):
            problems.append("restored commit range is not contiguous")
        expected, tokens = set(), {}
        for definition in connection.execute("SELECT * FROM index_defs"):
            for row in visible_rows(connection, definition["collection"], head):
                token = scalar_token(field(loads(row["body"]), definition["field"]))
                if token is None:
                    continue
                if definition["unique_flag"]:
                    bucket = tokens.setdefault((definition["collection"], definition["name"]), set())
                    if token in bucket:
                        problems.append("unique index has duplicate values: " + definition["name"])
                    bucket.add(token)
                expected.add((definition["collection"], definition["name"], token, row["key"]))
        actual = {tuple(row) for row in connection.execute(
            "SELECT collection,name,token,key FROM index_values")}
        if expected != actual:
            problems.append("index projection differs from visible documents")
        return problems
