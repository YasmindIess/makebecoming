#!/usr/bin/env python3
"""Chapter 6: test native coarse projection and its nonunique inverse."""
import itertools, json, pathlib, subprocess, tempfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
BIN=ROOT/'forge-kernel'
INPUT=ROOT/'examples/v2_1_verified.jsonl'
def run(path):
    return subprocess.run([str(BIN),'occlude',str(path)],text=True,capture_output=True)
p=run(INPUT)
assert p.returncode==0,p.stderr
d=json.loads(p.stdout)
assert d['schema']=='forge.occlusion.v1'
assert d['producer_verified'] is True and d['attestation']=='none'
assert d['privacy']=='projection-only-not-network-anonymity'
assert [(b['min'],b['max']) for b in d['micro']['bands']]==[(0,3),(8,11),(0,3)]
assert d['meso']['compatible_edges']==[[3,1]]
assert d['macro']=={'regions':2,'compatible_contacts':1}
assert d['regeneration']['status']=='enumerated'
assert d['regeneration']['candidate_count']==45
assert d['regeneration']['examples'][:3]==[[0,8,0],[0,8,1],[0,9,0]]
for forbidden in ('origin_strand','origin_x_milli','lambda_milli','boundary_x_milli','event_cid','source_head','parent_hash','affected_strands'):
    assert '"'+forbidden+'"' not in p.stdout, forbidden
assert p.stdout==run(INPUT).stdout
choices=[range(x['min'],x['max']+1) for x in d['micro']['bands']]
edges={tuple(x) for x in d['meso']['compatible_edges']}
solutions=[list(xs) for xs in itertools.product(*choices) if all(((i-j<=3) and abs(xs[i]-xs[j])<=6)==((i+1,j+1) in edges) for i in range(len(xs)) for j in range(i))]
assert len(solutions)==45 and solutions[:6]==d['regeneration']['examples']
with tempfile.TemporaryDirectory() as td:
    bad=pathlib.Path(td)/'tampered.jsonl'
    bad.write_text(INPUT.read_text().replace('"origin_strand":3','"origin_strand":4',1))
    out=run(bad)
    assert out.returncode!=0 and not out.stdout
assert 'published' in d['limitations']
print('OCCLUSION PASS: 3 bands, 1 compatible edge, 45 inverse images, no exact fields, determinism, tamper rejection')
