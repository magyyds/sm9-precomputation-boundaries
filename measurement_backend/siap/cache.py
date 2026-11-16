"""Fixed-space authenticated cache policies. Q-only optimization, no fake delays."""
import ctypes as C
import hashlib
import time

class Cache:
    METHODS = ('cold', 'immediate', 'lru', 'tinylfu', 'siap')

    def __init__(self, crypto, method='siap', budget=262144, threshold=2, request_build=None):
        if method not in self.METHODS or threshold < 1: raise ValueError('cache configuration')
        self.crypto, self.method, self.threshold = crypto, method, threshold
        self.request_build = request_build
        class Slot(C.Structure):
            _fields_ = [('state', C.c_uint8), ('identity', C.c_ubyte * 40),
                        ('count', C.c_uint64), ('last', C.c_uint64), ('keep', C.c_uint64),
                        ('hits', C.c_uint64), ('generation', C.c_uint64), ('q', C.c_ubyte * crypto.q_size)]
        self.slot_type = Slot
        self.sketch = bytearray(4096) if method == 'tinylfu' else bytearray()
        available = budget - len(self.sketch)
        self.capacity = max(0, available // C.sizeof(Slot)) if method != 'cold' else 0
        if available < 0: raise ValueError('A budget below sketch size')
        self.slots = (Slot * self.capacity)()
        self.allocated_bytes = C.sizeof(self.slots) + len(self.sketch)
        self.auth_events = self.builds = self.evictions = self.build_cpu_ns = 0
        self.unused_builds = 0
        self.sequence = self.build_requests = self.build_cancelled = self.build_failed = 0

    def _indexes(self, identity):
        h = hashlib.blake2s(identity, digest_size=8, person=b'SIAPv1').digest()
        return [row * 2048 + (int.from_bytes(h[row*2:row*2+2], 'big') % 2048) for row in range(4)]

    def _get(self, i): return (self.sketch[i // 2] >> (4 * (i % 2))) & 15

    def _frequency(self, identity): return min(self._get(i) for i in self._indexes(identity))

    def _increment(self, identity):
        self.auth_events += 1
        for i in self._indexes(identity):
            value = self._get(i)
            if value < 15: self.sketch[i//2] += 1 << (4 * (i % 2))
        if self.auth_events % 10000 == 0:
            for i, b in enumerate(self.sketch): self.sketch[i] = ((b >> 1) & 7) | ((b >> 1) & 112)

    def find(self, identity):
        return next((s for s in self.slots if s.state and bytes(s.identity) == identity), None)

    def lookup(self, identity):
        s = self.find(identity)
        return s.q if s is not None and s.state == 2 else None

    def _clear(self, slot):
        if slot.state == 2 and slot.hits == 0: self.unused_builds += 1
        slot.state = 0

    def expire(self, now, revoked=()):
        for s in self.slots:
            if s.state and (now > s.keep or bytes(s.identity).hex() in revoked): self._clear(s)

    def accepted(self, identity, fresh, hit, now, keep):
        if self.method == 'cold': return
        if self.method == 'tinylfu': self._increment(identity)
        slot = self.find(identity)
        if slot is not None:
            slot.last = now
            if hit: slot.hits += 1
            if slot.state in (2, 3): return
        if slot is None:
            # First successful message is sunk cost for SIAP; no lease credit.
            if self.method == 'siap' and fresh: return
            if self.capacity == 0: return
            slot = next((s for s in self.slots if not s.state), None)
            if slot is None:
                slot = min(self.slots, key=lambda s: (s.last, bytes(s.identity)))
                if self.method == 'tinylfu' and self._frequency(identity) <= self._frequency(bytes(slot.identity)): return
                self.evictions += 1; self._clear(slot)
            slot.identity[:] = identity; slot.count = 0; slot.hits = 0
            self.sequence += 1; slot.generation = self.sequence
            slot.keep = keep; slot.last = now; slot.state = 1
        slot.count += 1
        if self.method != 'siap' or slot.count >= self.threshold:
            if self.request_build is not None:
                if self.request_build(identity, slot.generation, keep):
                    self.build_requests += 1; slot.state = 3
                return
            start = time.thread_time_ns()
            self.crypto.build(identity, slot.q)
            self.build_cpu_ns += time.thread_time_ns() - start
            self.builds += 1; slot.state = 2

    def complete(self, identity, generation, q, cpu_ns, valid):
        self.builds += 1; self.build_cpu_ns += cpu_ns
        slot = self.find(identity)
        if slot is None or slot.generation != generation or slot.state != 3 or not valid:
            self.build_cancelled += 1
            if slot is not None and slot.generation == generation: self._clear(slot)
            return False
        if q is None:
            self.build_failed += 1; slot.state = 1
            return False
        slot.q[:] = bytes(q); slot.state = 2
        return True

    def metrics(self):
        return {'a_allocated_bytes': self.allocated_bytes, 'a_capacity': self.capacity,
                'a_active': sum(s.state != 0 for s in self.slots), 'builds': self.builds,
                'build_cpu_ns': self.build_cpu_ns, 'evictions': self.evictions,
                'build_requests': self.build_requests, 'build_cancelled': self.build_cancelled,
                'build_failed': self.build_failed,
                'unused_builds': self.unused_builds + sum(s.state == 2 and s.hits == 0 for s in self.slots)}


class NoReserveCache(Cache):
    """Threshold admission with bounded metadata, but no table slot lease.

    One eighth of A (at most 4096 bytes) is assigned to counting metadata;
    completed tables compete for the remaining A only at publication time.
    This split is fixed before a run, not chosen from its results.
    """
    def __init__(self,crypto,method='noreserve',budget=262144,threshold=2,request_build=None):
        class Meta(C.Structure):
            _fields_=[('state',C.c_uint8),('identity',C.c_ubyte*40),('count',C.c_uint64),
                      ('last',C.c_uint64),('keep',C.c_uint64),('generation',C.c_uint64)]
        meta_budget=min(4096,budget//8)
        self.metadata=(Meta*(meta_budget//C.sizeof(Meta)))()
        super().__init__(crypto,'siap',budget-C.sizeof(self.metadata),threshold,request_build)
        self.method='noreserve';self.allocated_bytes+=C.sizeof(self.metadata)
        self.scratch=C.create_string_buffer(crypto.q_size) if request_build is None else None
        self.metadata_evictions=0

    def _meta(self,identity):return next((s for s in self.metadata if s.state and bytes(s.identity)==identity),None)

    def expire(self,now,revoked=()):
        super().expire(now,revoked)
        for s in self.metadata:
            if s.state and (now>s.keep or bytes(s.identity).hex() in revoked):s.state=0

    def accepted(self,identity,fresh,hit,now,keep):
        ready=self.find(identity)
        if ready is not None:
            ready.last=now;ready.hits+=int(hit);return
        if fresh or not self.capacity or not len(self.metadata):return
        meta=self._meta(identity)
        if meta is None:
            meta=next((s for s in self.metadata if not s.state),None)
            if meta is None:
                meta=min(self.metadata,key=lambda s:(s.last,bytes(s.identity)));self.metadata_evictions+=1
            self.sequence+=1;meta.generation=self.sequence
            meta.state=1;meta.identity[:]=identity;meta.count=0;meta.keep=keep
        meta.last=now
        if meta.state==3:return
        meta.count+=1
        if meta.count<self.threshold:return
        if self.request_build is not None:
            if self.request_build(identity,meta.generation,keep):meta.state=3;self.build_requests+=1
        else:
            start=time.thread_time_ns();self.crypto.build(identity,self.scratch)
            meta.state=3;self.complete(identity,meta.generation,self.scratch,time.thread_time_ns()-start,True)

    def complete(self,identity,generation,q,cpu_ns,valid):
        self.builds+=1;self.build_cpu_ns+=cpu_ns;meta=self._meta(identity)
        if meta is None or meta.generation!=generation or meta.state!=3 or not valid:
            self.build_cancelled+=1
            if meta is not None and meta.generation==generation:meta.state=0
            return False
        if q is None:self.build_failed+=1;meta.state=1;return False
        slot=next((s for s in self.slots if not s.state),None)
        if slot is None:
            slot=min(self.slots,key=lambda s:(s.last,bytes(s.identity)));self.evictions+=1;self._clear(slot)
        slot.identity[:]=identity;slot.generation=generation;slot.keep=meta.keep;slot.last=meta.last
        slot.count=meta.count;slot.hits=0;slot.q[:]=bytes(q);slot.state=2;meta.state=0
        return True

    def metrics(self):
        return {**super().metrics(),'metadata_bytes':C.sizeof(self.metadata),'metadata_capacity':len(self.metadata),
                'metadata_active':sum(s.state!=0 for s in self.metadata),'metadata_evictions':self.metadata_evictions,
                'synchronous_scratch_bytes':C.sizeof(self.scratch) if self.scratch is not None else 0}
