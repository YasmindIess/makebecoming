#!/usr/bin/env python3
"""Chapter 5: test the verified native field and relational classification."""
import json, pathlib, subprocess, tempfile
ROOT = pathlib.Path(__file__).resolve().parents[1]
BIN = ROOT / 'forge-kernel'
SOURCE = ROOT / 'examples/v2_1_verified.jsonl'

def field(path):
    return subprocess.run([str(BIN), 'field', str(path)], text=True, capture_output=True)

ok = field(SOURCE)
assert ok.returncode == 0, ok.stderr
f = json.loads(ok.stdout)
assert f['schema'] == 'forge.field.v1'
assert f['source_head'].startswith('sha256:')
assert [(n['generation'], n['position']) for n in f['micro']['nodes']] == [(0,3),(1,10),(2,0)]
assert (f['macro']['candidate_contacts'], f['macro']['compatible_contacts'], f['macro']['regions']) == (3,1,2)
assert (f['simplicial']['vertices'],f['simplicial']['edges'],f['simplicial']['faces'],f['simplicial']['tetrahedra']) == (27,65,57,18)
assert f['simplicial']['boundary_squared_zero']
match = [c for c in f['meso']['contacts'] if (c['tau'],c['delta']) == (2,3)]
assert len(match) == 1 and match[0]['compatible'] and match[0]['invariant'] == 6 and match[0]['overlap'] == 4
n1,n3 = f['micro']['nodes'][0],f['micro']['nodes'][2]
assert 3*n1['generation']+2*n1['position'] == 3*n3['generation']+2*n3['position'] == 6
assert [m['count'] for m in f['meso']['motifs']] == [1,1,1]
assert ok.stdout == field(SOURCE).stdout, 'Field must be byte-for-byte deterministic'
with tempfile.TemporaryDirectory() as tmp:
    invalid = pathlib.Path(tmp)/'bad.jsonl'
    raw = SOURCE.read_text()
    invalid.write_text(raw.replace('"origin_strand":3','"origin_strand":4',1))
    bad = field(invalid)
    assert bad.returncode != 0 and 'ERROR' in bad.stderr
print('FIELD PASS: positions, diagonal invariant, compatibility, two macro regions, native topology, deterministic output, tamper rejection')
