"""Versioned, fixed-payload cache policies with pre-verification lease tokens.

Only the caller's final Accept may call accepted(). prepare() may replace A for
an identity accepted previously; it NEVER changes R. Invalid requests cannot
earn credit or refresh authenticated recency, but can cause speculative A churn.
Python/runtime and native stack memory are outside the explicit payload budget.
"""
import ctypes as C
import hashlib
import time
from .cache import Cache


class CacheV3(Cache):
    METHODS = ('cold', 'lru', 'immediate', 'tinylfu', 'wtinylfu', 'twohit', 'siap')

    def __init__(self, crypto, method='siap', budget=65536, threshold=2,
                 request_build=None):
        if method not in self.METHODS or threshold < 0:
            raise ValueError('cache configuration')
        if method == 'siap' and threshold == 0 and not hasattr(crypto, 'retained'):
            raise ValueError('B=0 requires an already available object; rebuilding is not retention')
        if request_build is not None and method != 'siap':
            raise ValueError('asynchronous mode currently supports SIAP only')
        self.door = bytearray(512) if method in ('tinylfu', 'wtinylfu') else bytearray()
        class Ghost(C.Structure):
            _fields_ = [('used', C.c_uint8), ('identity', C.c_ubyte * 40),
                        ('last', C.c_uint64), ('keep', C.c_uint64)]
        self.ghosts = (Ghost * (4096 // C.sizeof(Ghost) if method == 'twohit' else 0))()
        # The sole worker's output is charged even while it is idle. Sync builds
        # write directly into their reserved slot; no second output buffer exists.
        self.workspace_bytes = crypto.q_size if request_build else 0
        extra = len(self.door) + C.sizeof(self.ghosts) + self.workspace_bytes
        base_method = 'tinylfu' if method in ('tinylfu', 'wtinylfu') else ('cold' if method == 'cold' else 'siap')
        super().__init__(crypto, base_method, budget-extra, max(1, threshold), request_build)
        self.method, self.threshold = method, threshold
        self.allocated_bytes += extra
        self.sample_size = max(32, 10*self.capacity)
        self.sample_events = self.reservations = self.charged_events = self.aging_resets = 0
        self.retentions = self.retention_cpu_ns = 0
        self.protected_capacity = max(0, int(.8*(self.capacity-1)))
        self.budget = budget

    def _door_indexes(self, identity):
        h = hashlib.blake2s(identity, digest_size=8, person=b'DoorV3').digest()
        return [int.from_bytes(h[k:k+2], 'big') % (8*len(self.door)) for k in (0, 2, 4)]

    def _present(self, identity):
        return all(self.door[k//8] & (1 << (k%8)) for k in self._door_indexes(identity))

    def _frequency(self, identity):
        return super()._frequency(identity) + int(self._present(identity))

    def _increment(self, identity):
        self.auth_events += 1
        self.sample_events += 1
        if self._present(identity):
            indexes = self._indexes(identity)
            smallest = min(self._get(k) for k in indexes)
            for k in indexes:
                if self._get(k) == smallest and smallest < 15:
                    self.sketch[k//2] += 1 << (4*(k%2))
        else:
            for k in self._door_indexes(identity): self.door[k//8] |= 1 << (k%8)
        if self.sample_events >= self.sample_size:
            for k, b in enumerate(self.sketch): self.sketch[k] = (b >> 1) & 0x77
            self.door[:] = bytes(len(self.door))
            self.sample_events //= 2
            self.aging_resets += 1

    @staticmethod
    def _lru(slots):
        return min(slots, key=lambda s: (s.last, bytes(s.identity)))

    def _new(self, slot, identity, last, keep, zone=0):
        if slot.state:
            self.evictions += 1
            self._clear(slot)
        self.sequence += 1
        slot.identity[:] = identity
        slot.generation = self.sequence
        slot.state, slot.count, slot.hits = 1, zone, 0
        slot.last, slot.keep = last, keep
        return slot

    def _empty_or_lru(self):
        return next((s for s in self.slots if not s.state), None) or self._lru(self.slots)

    def prepare(self, identity, eligible, now, keep, last_authenticated=0):
        """Return a generation token BEFORE crypto. Replays never use accepted()."""
        if self.method != 'siap' or not eligible or not self.capacity: return None
        slot = self.find(identity)
        if slot is None:
            slot = self._new(self._empty_or_lru(), identity, last_authenticated, keep)
            self.reservations += 1
        return (bytes(identity), int(slot.generation), int(slot.state))

    def _build(self, identity, slot, keep):
        if self.request_build is not None:
            if self.request_build(identity, slot.generation, keep):
                self.build_requests += 1
                slot.state = 3
            return
        started = time.thread_time_ns()
        self.build_requests += 1
        try:
            self.crypto.build(identity, slot.q)
        except Exception:
            self.build_failed += 1
            slot.state = 4
            raise
        finally:
            self.build_cpu_ns += time.thread_time_ns()-started
            self.builds += 1
        slot.state = 2

    def complete(self, identity, generation, q, cpu_ns, valid):
        ok = super().complete(identity, generation, q, cpu_ns, valid)
        slot = self.find(identity)
        if not ok and q is None and slot is not None and slot.generation == generation:
            slot.state = 4  # Do not retry an already attempted build in this lease.
        return ok

    def _window_slot(self):
        """One-entry LRU window feeding a TinyLFU-admitted segmented LRU main."""
        win = next((s for s in self.slots if s.state and s.count == 1), None)
        empty = next((s for s in self.slots if not s.state), None)
        if win is None: return empty or self._lru(self.slots)
        if empty is not None:
            win.count = 2
            return empty
        main = [s for s in self.slots if s.state and s.count != 1]
        if not main: return win
        probation = [s for s in main if s.count == 2]
        victim = self._lru(probation or main)
        if self._frequency(bytes(win.identity)) > self._frequency(bytes(victim.identity)):
            win.count = 2
            return victim
        return win

    def _touch_segment(self, slot):
        if slot.count == 2 and self.protected_capacity:
            slot.count = 3
            protected = [s for s in self.slots if s.state and s.count == 3]
            if len(protected) > self.protected_capacity: self._lru(protected).count = 2

    def accepted(self, identity, fresh, hit, now, keep, token=None):
        if self.method == 'cold': return
        if self.method in ('tinylfu', 'wtinylfu'): self._increment(identity)
        slot = self.find(identity)
        if self.method == 'siap':
            # B=0 means immediate retention; the first Accept is eligible here.
            if self.threshold == 0 and slot is None and self.capacity:
                started = time.thread_time_ns()
                available = self.crypto.retained(identity)
                if available is None or C.sizeof(available) != self.crypto.q_size:
                    raise ValueError('retained object unavailable')
                slot = self._new(self._empty_or_lru(), identity, now, keep)
                slot.q[:] = bytes(available)
                slot.state = 2
                self.retentions += 1
                self.retention_cpu_ns += time.thread_time_ns()-started
                return
            if token is None or slot is None or token[:2] != (bytes(identity), slot.generation): return
            slot.last = now
            if hit: slot.hits += 1
            if token[2] != 1 or slot.state != 1: return
            slot.count += 1
            self.charged_events += 1
            if slot.count >= self.threshold: self._build(identity, slot, keep)
            return
        if slot is not None:
            slot.last = now
            slot.hits += int(hit)
            if self.method == 'wtinylfu': self._touch_segment(slot)
            return
        if not self.capacity: return
        if self.method == 'twohit':
            ghost = next((g for g in self.ghosts if g.used and bytes(g.identity) == identity), None)
            if ghost is None:
                ghost = next((g for g in self.ghosts if not g.used), None) or self._lru(self.ghosts)
                ghost.used = 1; ghost.identity[:] = identity; ghost.last = now; ghost.keep = keep
                return
            ghost.used = 0
        if self.method == 'wtinylfu':
            slot = self._window_slot()
        else:
            slot = self._empty_or_lru()
            if slot.state and self.method == 'tinylfu' and self._frequency(identity) <= self._frequency(bytes(slot.identity)): return
        self._new(slot, identity, now, keep, 1 if self.method == 'wtinylfu' else 0)
        self._build(identity, slot, keep)

    def expire(self, now, revoked=()):
        super().expire(now, revoked)
        for g in self.ghosts:
            if g.used and (now > g.keep or bytes(g.identity).hex() in revoked): g.used = 0

    def metrics(self):
        return {**super().metrics(), 'revision': 'v3-preverify-token',
                'workspace_bytes_in_a': self.workspace_bytes, 'sketch_bytes': len(self.sketch),
                'doorkeeper_bytes': len(self.door), 'ghost_bytes': C.sizeof(self.ghosts),
                'reservations': self.reservations, 'charged_events': self.charged_events,
                'retentions': self.retentions, 'retention_cpu_ns': self.retention_cpu_ns,
                'aging_resets': self.aging_resets, 'sample_size': self.sample_size,
                'a_budget': self.budget}
