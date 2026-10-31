#!/usr/bin/env python3
"""Independent Python fixture / rejection tests for Forge V2.1 restricted schema."""
import json, hashlib, subprocess, pathlib, tempfile, copy
ROOT = pathlib.Path(__file__).resolve().parents[1]
KERNEL = ROOT / 'forge-kernel'
DOMAIN = b'FORGE/OMISSION/V3\n'

def canon(x):
    return json.dumps(x, sort_keys=True, separators=(',', ':'), ensure_ascii=True)

def event(seq, lat, regen, parent):
    strand = ((seq-1)*7+3)%17
    x = 125 + (((seq-1)*53)%230)
    amp = 38 + ((seq*19)%38)
    body = {
        'schema':'forge.omission.v3','kind':'omission.simulated','seq':seq,
        'seed':137,'model':'forge-confluence.v1',
        'origin_x_milli':x*1000,'origin_strand':strand,
        'lambda_milli':lat,'regen_milli':regen,
        'boundary_x_milli':x*1000+75000+390*lat,
        'affected_strands':[i for i in range(17) if abs(i-strand)<=3],
        'amplitude_milli':amp*1000,'sim_time_ms':seq*1000,
        'parent_hash':parent,
    }
    digest='sha256:'+hashlib.sha256(DOMAIN+canon(body).encode()).hexdigest()
    return {'body':body,'digest':digest}

def run(*args, good=True):
    r=subprocess.run([str(KERNEL),*map(str,args)],capture_output=True,text=True)
    if good and r.returncode: raise AssertionError(r.stderr)
    if not good and r.returncode==0: raise AssertionError('expected rejection')
    return r

def main():
    records=[]
    for seq,(lat,regen) in enumerate([(430,620),(780,300),(120,900)],start=1):
        records.append(event(seq,lat,regen,records[-1]['digest'] if records else None))
    (ROOT/'examples'/'v2_1_verified.jsonl').write_text(''.join(canon(r)+'\n' for r in records),encoding='utf-8')
    with tempfile.TemporaryDirectory() as td:
        p=pathlib.Path(td)/'events.jsonl'
        d=pathlib.Path(td)/'topology.jsonl'
        p.write_text(''.join(canon(r)+'\n' for r in records),encoding='utf-8')
        data=json.loads(run('replay',p,'--topology',d).stdout)
        assert data['events']==3 and data['verified'] and data['head']==records[-1]['digest']
        assert data['boundary_squared_zero'] is True
        assert data['vertices']==sum(3+len(r['body']['affected_strands']) for r in records)
        assert data['tetrahedra']==sum(len(r['body']['affected_strands']) for r in records)
        assert data['connected_components']==1
        assert data['euler_characteristic']==1
        topo=[json.loads(s) for s in d.read_text().splitlines()]
        assert sum(x['kind']=='simplex' and x['dimension']==3 for x in topo)==data['tetrahedra']
        first=d.read_bytes()
        run('replay',p,'--topology',d)
        assert d.read_bytes()==first, 'non-deterministic topology'
        for vertices,expected in [('1', (1,0,0,0)),('1,2',(2,1,0,0)),('3,1,2',(3,3,1,0)),('4,2,1,3',(4,6,4,1))]:
            res=json.loads(run('simplex',vertices).stdout)
            assert (res['vertices'],res['edges'],res['faces'],res['tetrahedra'])==expected
            assert res['boundary_squared_zero']
        corrupted=copy.deepcopy(records)
        corrupted[1]['body']['boundary_x_milli']+=1
        p.write_text(''.join(canon(r)+'\n' for r in corrupted))
        assert 'mismatch' in run('replay',p,good=False).stderr
        corrupted=copy.deepcopy(records)
        corrupted[1]['body']['parent_hash']='sha256:'+'0'*64
        p.write_text(''.join(canon(r)+'\n' for r in corrupted))
        assert 'parent hash chain mismatch' in run('replay',p,good=False).stderr
        corrupted=copy.deepcopy(records)
        corrupted[0]['body']['model']='danger.ClassName'
        p.write_text(''.join(canon(r)+'\n' for r in corrupted))
        assert 'mismatch' in run('replay',p,good=False).stderr
        corrupted=copy.deepcopy(records)
        corrupted[0]['digest']='sha256:'+'0'*64
        p.write_text(''.join(canon(r)+'\n' for r in corrupted))
        assert 'SHA-256 mismatch' in run('replay',p,good=False).stderr
        corrupted=copy.deepcopy(records)
        corrupted[0]['body']['unapproved']='x'
        p.write_text(''.join(canon(r)+'\n' for r in corrupted))
        assert 'unknown body property' in run('replay',p,good=False).stderr
        p.write_text(canon(records[0])+'\n')
        one=json.loads(run('replay',p).stdout)
        assert one['events']==1 and one['connected_components']==1
        p.write_text('')
        zero=json.loads(run('replay',p).stdout)
        assert zero['events']==0 and zero['head'] is None
    print('R0 PASS: 3-event verified replay, 18 tetrahedra, closure, deterministic topology, 0–3-simplex math, 5 tamper/invalid rejections, cold replay')
if __name__=='__main__': main()
