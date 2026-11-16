import unittest
from siap.analysis import paired_bootstrap,quantile
from siap.state import advance

class AnalysisTests(unittest.TestCase):
    def test_bootstrap_constant_difference(self):
        a={i:.8 for i in range(30)}; b={i:.7 for i in range(30)}
        r=paired_bootstrap(a,b,repeats=200)
        self.assertAlmostEqual(r['mean_difference'],.1)
        for v in r['ci95']: self.assertAlmostEqual(v,.1)
        self.assertFalse(r['exploratory'])
    def test_unpaired_or_missing_endpoint_rejected(self):
        with self.assertRaises(ValueError): paired_bootstrap({1:.5},{2:.5})
        with self.assertRaises(ValueError): paired_bootstrap({1:None,2:.5},{1:.5,2:.6})
    def test_small_sample_p99_not_invented(self): self.assertIsNone(quantile([], .99))
    def test_randomized_replay_oracle(self):
        import random
        rng=random.Random(51); seen=set(); high=None; bits=0
        for _ in range(10000):
            c=rng.randrange(1000)
            expected=c not in seen and (high is None or c>high-64)
            result=advance(high,bits,c,64)
            self.assertEqual(result is not None,expected)
            if result is not None: high,bits=result; seen.add(c)

    def test_denominator_keeps_losses(self):
        import json,tempfile
        from pathlib import Path
        from siap.analysis import summarize
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp)
            for folder in ('scenario','sender','receiver'): (base/folder).mkdir()
            plan=[{'index':i,'kind':'legitimate','phase':'observe','packet_sha256':str(i)} for i in range(4)]
            (base/'scenario/plan.jsonl').write_text('\n'.join(json.dumps(p) for p in plan))
            (base/'scenario/scenario.json').write_text('{"seed":1}')
            sent=[{'index':i,'scheduled_ns':0,'reason':'sender_missed' if i==3 else 'sent'} for i in range(4)]
            (base/'sender/sender.jsonl').write_text('\n'.join(json.dumps(p) for p in sent))
            events=[{'packet_sha256':'0','identity':'a','counter':0,'verified_ns':1,'accepted_ns':2,
                     'handed_off_ns':3,'ingress_ns':0,'reason':'delivered'},
                    {'packet_sha256':'1','reason':'queue_drop'}]
            (base/'receiver/events.jsonl').write_text('\n'.join(json.dumps(p) for p in events))
            r=summarize(base/'scenario',base/'sender',base/'receiver')
            self.assertEqual(r['n_scheduled'],4); self.assertEqual(r['p_delivered'],.25)
            self.assertEqual(r['terminal_counts']['queue_drop'],1)
            self.assertEqual(r['terminal_counts']['network_missing'],1)
            self.assertEqual(r['terminal_counts']['sender_missed'],1)
            self.assertIsNone(r['p_timely'])

    def test_comparison_rejects_different_workloads(self):
        import json,tempfile
        from pathlib import Path
        from siap.analysis import compare_files
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);left=[];right=[]
            for seed in (1,2):
                row={'seed':seed,'p_timely':.8,'n_scheduled':24,'workload_sha256':str(seed),
                     'deadline_ms':100,'signing_mode':'online_signing','comparison_parameters':{'rate':4}}
                for group,paths in (('a',left),('b',right)):
                    p=root/f'{group}-{seed}.json';p.write_text(json.dumps(row));paths.append(p)
            self.assertEqual(compare_files(left,right)['mean_difference'],0)
            bad=json.loads(right[0].read_text());bad['workload_sha256']='different';right[0].write_text(json.dumps(bad))
            with self.assertRaises(ValueError):compare_files(left,right)
