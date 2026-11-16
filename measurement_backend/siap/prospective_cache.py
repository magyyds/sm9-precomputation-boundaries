"""Experimental post-Accept gain admission. This is NOT the v3 lease theorem.

History and predictions never authorize messages. Only a caller's unique final
Accept can mutate this module; verification lookup/prepare is read-only. No
extra native table space is held by an unbuilt candidate. Fixed-size history
is charged within A. Predictions use authenticated event distance, not seconds.
"""
import ctypes as C
from .cache_v3 import CacheV3


class History(C.Structure):
    _fields_=[('used',C.c_uint8),('identity',C.c_ubyte*40),
              ('seen',C.c_uint16),('frequency',C.c_uint16),
              ('last_event',C.c_uint64),('gap',C.c_double),('keep',C.c_uint64)]


class ProspectiveCache(CacheV3):
    VARIANTS=('gain','gain_no_victim','gain_no_cost','lfu2')
    def __init__(self,crypto,variant='gain',budget=65536,build_ns=1,delta_ns=1):
        if variant not in self.VARIANTS or build_ns<0 or delta_ns<=0:
            raise ValueError('positive calibrated savings required')
        self.history=(History*64)()
        history_bytes=C.sizeof(self.history)
        super().__init__(crypto,'lru',budget-history_bytes,1)
        self.variant=variant;self.budget=budget;self.allocated_bytes+=history_bytes
        self.build_cost=float(build_ns);self.delta=float(delta_ns)
        self.horizon=max(1,10*self.capacity)
        self.events=0;self.history_evictions=0;self.cost_rejects=0;self.victim_rejects=0
        self.frequency_resets=0

    def _history(self,identity):
        return next((h for h in self.history if h.used and bytes(h.identity)==identity),None)

    def _observe(self,identity,keep):
        self.events+=1
        h=self._history(identity)
        if h is None:
            h=next((h for h in self.history if not h.used),None)
            if h is None:
                h=min(self.history,key=lambda h:(h.last_event,bytes(h.identity)))
                self.history_evictions+=1
            h.used=1;h.identity[:]=identity;h.seen=0;h.frequency=0;h.gap=0
        if h.seen:
            interval=self.events-h.last_event
            h.gap=float(interval) if h.seen==1 else .5*h.gap+.5*interval
        h.seen=min(65535,h.seen+1);h.frequency=min(15,h.frequency+1)
        h.last_event=self.events;h.keep=keep
        # Exact bounded counters, decayed with the same small-cache scale as
        # TinyLFU. All variants pay the same history-observation work.
        if self.events % self.horizon==0:
            for item in self.history:item.frequency//=2
            self.frequency_resets+=1
        return h

    def _future_hits(self,h):
        if h is None or h.seen<2:return 0.0
        distance=max(1.0,h.gap,float(self.events-h.last_event))
        return self.horizon/distance

    def accepted(self,identity,fresh,hit,now,keep,token=None):
        h=self._observe(identity,keep)
        slot=self.find(identity)
        if slot is not None:
            slot.last=now;slot.hits+=int(hit)
            return
        if not self.capacity or h.seen<2:return
        free=next((s for s in self.slots if not s.state),None)
        if self.variant=='lfu2':
            # Strong composition control: exact two-observation qualification
            # plus aged-frequency admission against an LRU table victim.
            victim=free if free is not None else self._lru(self.slots)
            old=self._history(bytes(victim.identity)) if victim.state else None
            if victim.state and h.frequency <= (old.frequency if old is not None else 0):
                self.victim_rejects+=1;return
        else:
            cost=0.0 if self.variant=='gain_no_cost' else self.build_cost
            net=self.delta*self._future_hits(h)-cost
            if net<=0:
                self.cost_rejects+=1;return
            if free is not None:victim=free
            elif self.variant=='gain_no_victim':victim=self._lru(self.slots)
            else:
                victim=min(self.slots,key=lambda s:(self._future_hits(self._history(bytes(s.identity))),s.last,bytes(s.identity)))
                retained=self.delta*self._future_hits(self._history(bytes(victim.identity)))
                if net<=retained:
                    self.victim_rejects+=1;return
        self._new(victim,identity,now,keep)
        self._build(identity,victim,keep)

    def expire(self,now,revoked=()):
        super().expire(now,revoked)
        for h in self.history:
            if h.used and (now>h.keep or bytes(h.identity).hex() in revoked):h.used=0

    def metrics(self):
        return {**super().metrics(),'revision':'prospective-no-lease','variant':self.variant,'history_bytes':C.sizeof(self.history),
                'history_capacity':len(self.history),'history_evictions':self.history_evictions,
                'horizon_events':self.horizon,'cost_rejects':self.cost_rejects,
                'victim_rejects':self.victim_rejects,'frequency_resets':self.frequency_resets,
                'predictions_are_not_guarantees':True}
