#!/usr/bin/env python3
"""Chapter 8: bounded autonomous proposals from verified native evidence."""
import copy
import json
import math
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
KERNEL = ROOT / 'forge-kernel'
SOURCE = ROOT / 'examples/v2_1_verified.jsonl'

def run(source, good=True):
    p=subprocess.run([str(KERNEL),'minima',str(source)],capture_output=True,text=True)
    assert (p.returncode == 0) == good, p.stderr
    return p.stdout

def test():
    raw=run(SOURCE)
    assert raw==run(SOURCE), 'native plan must be deterministic'
    data=json.loads(raw)
    assert data['schema']=='forge.confluence.v1'
    assert data['source_head']=='sha256:f67db906add73586646f18f1e5ccfee4de5a61edd77401f3254c90fc8dd4781f'
    assert data['events']==3 and len(data['branches'])==2
    m=data['model'];a=m['stiffness'];s=m['target'];d=m['residual']
    energy=lambda q:a*(q*q-.64)**2+4*(q-s)**2+.008*d
    grad=lambda q:4*a*q*(q*q-.64)+8*(q-s)
    for b in data['branches']:
        assert b['stable'] and 0 < b['steps'] <= 96
        assert len(b['trace'])==b['steps']+1
        for i,(q,e) in enumerate(b['trace']):
            assert abs(e-energy(q)) < 1.1e-4
            if i: assert e <= b['trace'][i-1][1]+1e-6
        assert abs(b['final_q']-b['trace'][-1][0])<1e-7
        assert abs(grad(b['final_q']))<.0001
        assert b['final_energy']<m['barrier_energy']
    left,right=data['branches']
    assert left['final_q']<0<right['final_q']
    r=data['reconciliation']
    assert r['candidate'] and r['preserve_both_branches'] and r['requires_grant']=='relation.assert'
    assert r['authorized'] is False and r['effect_committed'] is False
    assert data['selection']['selected_for_commit'] is False
    assert data['limits']['external_effects'] is False
    with tempfile.TemporaryDirectory() as td:
        f=pathlib.Path(td)/'altered.jsonl'
        rows=[json.loads(x) for x in SOURCE.read_text().splitlines()]
        rows[1]['body']['lambda_milli']+=1
        f.write_text(''.join(json.dumps(x,separators=(',',':'))+'\n' for x in rows))
        run(f,good=False)
        f.write_text('')
        z=json.loads(run(f))
        assert z['events']==0 and not z['reconciliation']['candidate']
    print('CONFLUENCE PASS: verified input, deterministic twin-basin descent, monotone energy, bounded search, authorized=false, tamper rejection')

if __name__=='__main__':test()