"""Explicit reference policies; metadata is separate from the table-slot budget.

Window-Frequency/LRU is an exact-window comparator inspired by frequency
admission, not an implementation of the TinyLFU sketch or W-TinyLFU.
LRU-2 uses the second-most-recent request index with retained finite-trace
history; no correlated-reference period. All requests are valid and distinct.
"""
from collections import OrderedDict, Counter, deque
METHODS=['Q-only','Immediate','Second-hit','Third-hit','LRU-2','Window-Frequency']

class Policy:
    def __init__(self, method, capacity, window=1024):
        self.method=method; self.capacity=capacity; self.window=window
        self.cache=OrderedDict(); self.history={}; self.freq=Counter(); self.recent=deque()
        self.t=0; self.unused=0; self.builds=0; self.hits=0; self.metadata_peak=0
        self.threshold={'Immediate':1,'Second-hit':2,'Third-hit':3}.get(method)
    def step(self,key):
        if self.method=='Q-only':return False,False
        self.t+=1
        if self.method=='Window-Frequency':
            self.recent.append(key);self.freq[key]+=1
            if len(self.recent)>self.window:
                old=self.recent.popleft();self.freq[old]-=1
                if self.freq[old]==0:del self.freq[old]
        elif self.method=='LRU-2':
            old=self.history.get(key,())
            self.history[key]=(old+(self.t,))[-2:]
        if key in self.cache:
            self.cache[key]+=1;self.cache.move_to_end(key);self.hits+=1
            return True,False
        if self.threshold is not None:
            self.history[key]=min(self.threshold,self.history.get(key,0)+1)
            accept=self.history[key]>=self.threshold
        else:accept=True
        victim=next(iter(self.cache)) if len(self.cache)==self.capacity else None
        if self.method=='Window-Frequency' and victim is not None:
            accept=self.freq[key]>self.freq[victim]
        elif self.method=='LRU-2' and victim is not None:
            # Infinite backward-2 distance takes priority; oldest last request breaks ties.
            victim=min(self.cache,key=lambda k:(len(self.history[k])>=2,self.history[k][0]))
        self.metadata_peak=max(self.metadata_peak,len(self.freq) if self.method=='Window-Frequency' else len(self.history))
        if accept:
            if victim is not None:self.unused+=int(self.cache.pop(victim)==0)
            self.cache[key]=0;self.builds+=1
        return False,accept
    def unused_count(self):return self.unused+sum(v==0 for v in self.cache.values())

def events(ids,method,capacity,window=1024):
    p=Policy(method,capacity,window);hits=[];builds=[]
    for key in ids:
        h,b=p.step(int(key));hits.append(h);builds.append(b)
    return hits,builds,p.unused_count(),p.metadata_peak
