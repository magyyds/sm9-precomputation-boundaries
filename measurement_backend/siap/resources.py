"""Measured memory categories. Overlapping RSS/tracemalloc views are not summed."""
import ctypes as C
import os
import resource
import sys
import tracemalloc
from pathlib import Path

def snapshot(receiver=None,queue_capacity=0):
    result={'pid':os.getpid(),'peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            'python_tracing_enabled':tracemalloc.is_tracing()}
    if tracemalloc.is_tracing():result['python_traced_current_bytes'],result['python_traced_peak_bytes']=tracemalloc.get_traced_memory()
    for name in ('smaps_rollup','status','io'):
        p=Path('/proc/self')/name
        if p.exists():result[name]=p.read_text()
    if receiver:
        result.update(replay_array_bytes=C.sizeof(receiver.ledger.records),acceleration_array_bytes=C.sizeof(receiver.cache.slots),
                      frequency_sketch_bytes=len(receiver.cache.sketch),
                      replay_python_wrapper_bytes=sys.getsizeof(receiver.ledger.records),
                      cache_python_wrapper_bytes=sys.getsizeof(receiver.cache.slots),
                      receiver_object_bytes=sys.getsizeof(receiver)+sys.getsizeof(receiver.__dict__),
                      async_scratch_bytes=C.sizeof(receiver.build_scratch) if receiver.build_scratch is not None else 0,
                      control_serialized_bytes=len(receiver.ledger.control_raw or b''),queue_capacity=queue_capacity,
                      sqlite_pager_target_kib=256,sqlite_page_count=receiver.ledger.db.execute('PRAGMA page_count').fetchone()[0] if receiver.ledger.db else 0)
        if hasattr(receiver.crypto,'entries'):result['certificate_array_bytes']=C.sizeof(receiver.crypto.entries)
        if hasattr(receiver.cache,'metadata'):
            result['noreserve_metadata_bytes']=C.sizeof(receiver.cache.metadata)
            result['noreserve_scratch_bytes']=C.sizeof(receiver.cache.scratch) if receiver.cache.scratch is not None else 0
    result['interpretation']='Fixed arenas are exact. RSS/PSS includes native heaps, interpreter, shared mappings and stacks. Tracemalloc overlaps RSS and excludes most native allocations; do not sum these views.'
    return result
