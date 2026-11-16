"""Bounded replay ledger and crash-persistent SQLite backing store.

The fixed array is the R working set. SQLite pager/control/interpreter memory
is separately accounted and is NOT included in R. No disk rollback protection.
"""
import ctypes as C
import sqlite3
import fcntl
import time
from pathlib import Path

ID_SIZE = 40

class Record(C.Structure):
    _fields_ = [('used', C.c_uint8), ('identity', C.c_ubyte * ID_SIZE),
                ('high', C.c_uint64), ('keep_us', C.c_uint64),
                ('bitmap', C.c_ubyte * 128)]

def advance(high, bitmap, counter, width):
    if not 0 <= counter < 2**64: return None
    if high is None: return counter, 1
    if counter > high:
        shift = counter - high
        return counter, 1 if shift >= width else ((bitmap << shift) | 1) & ((1 << width) - 1)
    distance = high - counter
    if distance >= width or bitmap & (1 << distance): return None
    return high, bitmap | (1 << distance)

class Ledger:
    def __init__(self, budget=262144, width=256, db=None, binding=''):
        if width not in (64, 256, 1024): raise ValueError('unsupported replay width')
        self.width = width
        self.capacity = budget // C.sizeof(Record)
        if self.capacity < 1: raise ValueError('R budget too small')
        self.records = (Record * self.capacity)()
        self.allocated_bytes = C.sizeof(self.records)
        self.db = None
        self.lockfile = None
        self.time_high = 0
        self.control_version = 0
        self.control_raw = None
        self.failed = False
        self.persist_count=self.persist_wall_ns=self.persist_max_ns=0
        if db:
            Path(db).parent.mkdir(parents=True, exist_ok=True)
            self.lockfile = open(str(db)+'.lock','a+b')
            try: fcntl.flock(self.lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                self.lockfile.close(); self.lockfile = None
                raise ValueError('ledger already owned by another receiver') from None
            self.db = sqlite3.connect(db, check_same_thread=False)
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('PRAGMA cache_size=-256')
            self.db.execute('CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v BLOB NOT NULL)')
            self.db.execute('CREATE TABLE IF NOT EXISTS replay (id BLOB PRIMARY KEY, high BLOB, bits BLOB, keep INTEGER)')
            expected = f'{width}:{self.capacity}:{binding}'
            found = self.meta('binding')
            if found is not None and found != expected: raise ValueError('ledger configuration/key binding changed')
            self.db.execute('INSERT OR IGNORE INTO meta VALUES (?,?)', ('binding', expected))
            self.db.commit()
            self.time_high = int(self.meta('time_high') or 0)
            self.control_version = int(self.meta('control_version') or 0)
            self.control_raw = self.meta('control_raw')
            rows = self.db.execute('SELECT id,high,bits,keep FROM replay ORDER BY id')
            for i, (identity, high, bits, keep) in enumerate(rows):
                if i >= self.capacity or len(identity) != ID_SIZE or len(bits) != 128 or len(high) != 8:
                    raise ValueError('corrupt/oversized ledger')
                self._write(i, identity, int.from_bytes(high, 'big'), int.from_bytes(bits, 'little'), keep)

    def meta(self, key):
        row = self.db.execute('SELECT v FROM meta WHERE k=?', (key,)).fetchone()
        return row[0] if row else None

    def _persist(self, statements):
        if self.failed: raise RuntimeError('storage failed; receiver closed')
        if self.db:
            started=time.monotonic_ns()
            try:
                with self.db:
                    for sql, args in statements: self.db.execute(sql, args)
            except Exception:
                self.failed = True
                raise
            finally:
                elapsed=time.monotonic_ns()-started;self.persist_count+=1
                self.persist_wall_ns+=elapsed;self.persist_max_ns=max(self.persist_max_ns,elapsed)

    def observe_time(self, now):
        if self.failed or now < self.time_high: return False
        self.time_high = now
        return True

    def install_control(self, version, raw):
        self._persist([
            ('INSERT OR REPLACE INTO meta VALUES (?,?)', ('control_version', str(version))),
            ('INSERT OR REPLACE INTO meta VALUES (?,?)', ('control_raw', raw)),
            ('INSERT OR REPLACE INTO meta VALUES (?,?)', ('time_high', str(self.time_high)))])
        self.control_version, self.control_raw = version, raw

    def find(self, identity):
        for i, r in enumerate(self.records):
            if r.used and bytes(r.identity) == identity: return i
        return None

    def gc(self, now):
        # Persist the time floor BEFORE deleting history.
        expired = [i for i, r in enumerate(self.records) if r.used and now > r.keep_us]
        if expired:
            self._persist([
                ('INSERT OR REPLACE INTO meta VALUES (?,?)', ('time_high', str(self.time_high))),
                ('DELETE FROM replay WHERE keep < ?', (now,))])
            for i in expired: self.records[i].used = 0

    def consume(self, identity, counter, keep_us, now):
        if len(identity) != ID_SIZE: raise ValueError('identity size')
        self.gc(now)
        slot = self.find(identity)
        fresh = slot is None
        if fresh:
            slot = next((i for i, r in enumerate(self.records) if not r.used), None)
            if slot is None: return 'ledger_capacity', False
            result = advance(None, 0, counter, self.width)
        else:
            r = self.records[slot]
            result = advance(r.high, int.from_bytes(r.bitmap, 'little'), counter, self.width)
        if result is None: return 'replay_reject', False
        high, bitmap = result
        self._persist([
            ('INSERT OR REPLACE INTO replay VALUES (?,?,?,?)',
             (identity, high.to_bytes(8, 'big'), bitmap.to_bytes(128, 'little'), keep_us)),
            ('INSERT OR REPLACE INTO meta VALUES (?,?)', ('time_high', str(self.time_high)))])
        self._write(slot, identity, high, bitmap, keep_us)
        return 'consumed', fresh

    def _write(self, slot, identity, high, bitmap, keep):
        r = self.records[slot]
        r.identity[:] = identity; r.high = high; r.keep_us = keep
        r.bitmap[:] = bitmap.to_bytes(128, 'little'); r.used = 1

    def close(self):
        if self.db: self.db.close(); self.db = None
        if self.lockfile:
            fcntl.flock(self.lockfile, fcntl.LOCK_UN)
            self.lockfile.close(); self.lockfile = None
