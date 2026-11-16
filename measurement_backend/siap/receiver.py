"""Atomic consume/final-check/accept with separate application handoff events."""
import hashlib
import threading
import time
import queue
import ctypes as C
from .crypto import Verifier
from .wire import decode
from .control import parse_snapshot
from .state import Ledger, Record
from .cache import Cache,NoReserveCache
from .cache_v3 import CacheV3

class Receiver:
    def __init__(self, public, authority_public, *, method='siap', threshold=2,
                 r_budget=262144, a_budget=262144, width=256, db=None,
                 max_age_us=100000, future_us=5000, control_age_us=2000000,
                 clock=None, hook=None, handoff=None, build_mode='sync', signature_backend=None,precompute='q',
                 policy_revision='legacy'):
        if build_mode not in ('sync', 'async'): raise ValueError('build mode')
        if policy_revision not in ('legacy', 'v3'): raise ValueError('policy revision')
        self.policy_revision = policy_revision
        self.crypto, self.authority = signature_backend or Verifier(public,precompute), Verifier(authority_public)
        self.lock = threading.RLock()
        self.clock = clock or (lambda: time.time_ns() // 1000)
        self.max_age_us, self.future_us, self.control_age_us = max_age_us, future_us, control_age_us
        if min(max_age_us, future_us, control_age_us) < 0: raise ValueError('time bounds')
        binding = hashlib.sha256(public + authority_public + getattr(self.crypto,'binding',b'') + f'{max_age_us}:{future_us}:{control_age_us}'.encode()).hexdigest()
        self.decoder = decode
        if signature_backend:
            if method!='cold' or build_mode!='sync': raise ValueError('SM2 uses its own certificate cache')
            from .sm2 import decode as sm2_decode
            self.decoder = sm2_decode
        # V3 tracks prior Accept separately from Consume. Reserve eight bytes per
        # R slot; restored records conservatively start with no Accept history.
        if policy_revision == 'v3':
            binding += ':v3'
            r_budget = (r_budget // (C.sizeof(Record)+8)) * C.sizeof(Record)
        self.ledger = Ledger(r_budget, width, db, binding)
        self.last_accept = (C.c_uint64 * (self.ledger.capacity if policy_revision == 'v3' else 0))()
        self.build_mode = build_mode
        self.build_jobs = queue.Queue(1)
        self.builder_busy = False
        self.builder = None
        self.builder_error = None
        self.build_scratch = C.create_string_buffer(self.crypto.q_size) if build_mode == 'async' else None
        cache_class = CacheV3 if policy_revision == 'v3' else (NoReserveCache if method=='noreserve' else Cache)
        self.cache = cache_class(self.crypto, method, a_budget, threshold,
                           self._request_build if build_mode == 'async' else None)
        self.control = None
        self.revoked = set()
        self.hook = hook or (lambda stage, receiver, message: None)
        self.handoff = handoff or (lambda message: None)
        self.closed = False
        if self.ledger.control_raw:
            self.control = parse_snapshot(self.ledger.control_raw, self.authority)
            if self.control['public_key'] != public.hex(): raise ValueError('restored key mismatch')
            self.revoked = set(self.control['revoked'])
        if build_mode == 'async':
            self.builder = threading.Thread(target=self._build_worker, name='siap-builder')
            self.builder.start()

    def _request_build(self, identity, generation, keep):
        # One total in-flight job, including the worker. No unbounded future list.
        if self.builder_busy or self.closed: return False
        self.builder_busy = True
        self.build_jobs.put_nowait((identity, generation, keep))
        return True

    def _build_worker(self):
        while True:
            job = self.build_jobs.get()
            if job is None: self.build_jobs.task_done(); return
            identity, generation, keep = job
            start = time.thread_time_ns(); result = None
            try:
                self.hook('build_started', self, None)
                self.crypto.build(identity, self.build_scratch)
                result = self.build_scratch
            except Exception as exc:
                self.builder_error = repr(exc)
            cpu_ns = time.thread_time_ns() - start
            try:
                with self.lock:
                    now = self.clock(); control = self.control
                    valid = (not self.closed and self.ledger.observe_time(now) and control is not None
                             and now <= keep and now <= control['expires_us']
                             and now-control['issued_us'] <= self.control_age_us and identity.hex() not in self.revoked)
                    self.cache.complete(identity, generation, result, cpu_ns, valid)
            except Exception as exc:
                self.builder_error=repr(exc);self.closed=True
            finally:
                with self.lock:self.builder_busy=False
                self.build_jobs.task_done()

    def drain_builds(self): self.build_jobs.join()

    def install(self, raw):
        new = parse_snapshot(raw, self.authority)
        with self.lock:
            now = self.clock()
            if not self.ledger.observe_time(now): raise ValueError('clock rollback')
            if new['version'] <= self.ledger.control_version: raise ValueError('control rollback')
            if new['public_key'] != self.crypto.public.hex(): raise ValueError('key rotation needs separate receiver')
            if new['issued_us'] > now + self.future_us or new['expires_us'] < now or now - new['issued_us'] > self.control_age_us:
                raise ValueError('control freshness')
            if self.control:
                for field in ('domain', 'key_version'):
                    if new[field] != self.control[field]: raise ValueError('control context changed')
                if not self.revoked.issubset(set(new['revoked'])): raise ValueError('revocation rollback')
                for e, interval in self.control['epochs'].items():
                    if e in new['epochs'] and new['epochs'][e] != interval: raise ValueError('epoch rewrite')
                    if e not in new['epochs']:
                        raise ValueError('epoch schedule removal requires new key namespace')
            self.ledger.install_control(new['version'], raw)
            self.control, self.revoked = new, set(new['revoked'])
            self.cache.expire(now, self.revoked)

    def _check(self, m, now):
        if self.closed or not self.ledger.observe_time(now): return 'clock_or_storage_reject'
        c = self.control
        if c is None or now > c['expires_us'] or now-c['issued_us'] > self.control_age_us: return 'control_expired'
        if (m.domain, m.key_version) != (c['domain'], c['key_version']): return 'context_reject'
        interval = c['epochs'].get(str(m.epoch))
        if interval is None: return 'epoch_reject'
        if m.identity().hex() in self.revoked: return 'revoked_reject'
        a, b = interval
        if not (a <= m.timestamp_us <= b and -self.future_us <= now-m.timestamp_us <= self.max_age_us
                and a-self.future_us <= now <= b+self.future_us): return 'stale_reject'
        return None

    def process(self, packet, ingress_ns=None):
        start_cpu = time.thread_time_ns()
        event = {'ingress_ns': ingress_ns if ingress_ns is not None else time.monotonic_ns(),
                 'dequeue_ns': time.monotonic_ns(), 'wire_bytes': len(packet),
                 'verified_ns': None, 'durably_consumed_ns': None, 'accepted_ns': None,
                 'handed_off_ns': None, 'cache_hit': False, 'reason': None}
        try:
            m, sig = self.decoder(packet)
        except (ValueError, OverflowError):
            event['reason'] = 'parse_reject'
            event['cpu_ns'] = time.thread_time_ns() - start_cpu
            return event
        event.update(identity=m.identity().hex(), counter=m.counter, timestamp_us=m.timestamp_us,
                     payload_bytes=len(m.payload))
        # One verifier core, serialized including cache build. Control installs can
        # occur at instrumented hooks; final check follows durable consumption.
        with self.lock:
            now = self.clock()
            reason = self._check(m, now)
            if reason is None:
                self.cache.expire(now, self.revoked)
                lease_token = None
                if self.policy_revision == 'v3':
                    previous = self.ledger.find(m.identity())
                    last = self.last_accept[previous] if previous is not None else 0
                    lease_token = self.cache.prepare(m.identity(), bool(last), now,
                        self.control['epochs'][str(m.epoch)][1], max(0, last-1))
                q = self.cache.lookup(m.identity())
                event['cache_hit'] = q is not None
                vstart = time.thread_time_ns()
                valid = self.crypto.verify(m.identity(), m.signed_bytes(), sig, q)
                event['verify_cpu_ns'] = time.thread_time_ns() - vstart
                if not valid: reason = 'signature_reject'
                else:
                    event['verified_ns'] = time.monotonic_ns()
                    self.hook('verified', self, m)
                    now = self.clock(); reason = self._check(m, now)
                    if reason is None and hasattr(self.crypto,'authorized') and not self.crypto.authorized(m.identity(),now):
                        reason='certificate_expired'
                    if reason is None:
                        keep = self.control['epochs'][str(m.epoch)][1] + self.max_age_us + self.future_us
                        self.hook('before_consume', self, m)
                        status, fresh = self.ledger.consume(m.identity(), m.counter, keep, now)
                        if self.policy_revision == 'v3' and fresh and status == 'consumed':
                            self.last_accept[self.ledger.find(m.identity())] = 0
                        if status != 'consumed': reason = status
                        else:
                            if self.ledger.db: event['durably_consumed_ns'] = time.monotonic_ns()
                            event['consumed_ns'] = time.monotonic_ns()
                            self.hook('consumed', self, m)
                            now = self.clock(); reason = self._check(m, now)
                            if reason is None and hasattr(self.crypto,'authorized') and not self.crypto.authorized(m.identity(),now):
                                reason='certificate_expired'
                            if reason is None:
                                event['accepted_ns'] = time.monotonic_ns()
                                event['control_version'] = self.control['version']
                                if self.policy_revision == 'v3':
                                    self.last_accept[self.ledger.find(m.identity())] = now+1
                                    self.cache.accepted(m.identity(), fresh, event['cache_hit'], now,
                                        self.control['epochs'][str(m.epoch)][1], lease_token)
                                self.hook('accepted', self, m)
            event['reason'] = reason
        if event['accepted_ns'] is not None:
            try:
                self.handoff(m)
                event['handed_off_ns'] = time.monotonic_ns()
                event['reason'] = 'delivered'
            except Exception:
                event['reason'] = 'application_error'
            self.hook('handed_off', self, m)
            with self.lock:
                now = self.clock()
                if self.policy_revision == 'legacy' and self._check(m, now) is None:
                    b = self.control['epochs'][str(m.epoch)][1]
                    # Synchronous construction competes for the same worker CPU.
                    self.cache.accepted(m.identity(), fresh, event['cache_hit'], now, b)
        event['cpu_ns'] = time.thread_time_ns() - start_cpu
        return event

    def metrics(self):
        return {**self.cache.metrics(), **(self.crypto.metrics() if hasattr(self.crypto,'metrics') else {}),
                'policy_revision': self.policy_revision, 'accept_history_bytes': C.sizeof(self.last_accept),
                'r_allocated_bytes': self.ledger.allocated_bytes + C.sizeof(self.last_accept),
                'precompute':getattr(self.crypto,'precompute','certificate'),'table_bytes':self.crypto.q_size,
                'build_mode': self.build_mode, 'build_scratch_bytes': self.crypto.q_size if self.builder else 0,
                'builder_error': self.builder_error,
                'storage_transactions':self.ledger.persist_count,'storage_total_wall_ns':self.ledger.persist_wall_ns,
                'storage_max_wall_ns':self.ledger.persist_max_ns,
                'r_capacity': self.ledger.capacity, 'r_active': sum(r.used != 0 for r in self.ledger.records),
                'persistence': 'sqlite_full_fsync' if self.ledger.db else 'ephemeral_test_only'}

    def close(self):
        self.closed = True
        if self.builder:
            self.build_jobs.put(None); self.builder.join(); self.builder = None
        self.ledger.close(); self.crypto.close(); self.authority.close()
