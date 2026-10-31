#!/usr/bin/env python3
"""Integration checks for native C + PHP local immutable blockstore."""
import json, os, pathlib, subprocess, tempfile
from test_r0 import event,canon
ROOT=pathlib.Path(__file__).resolve().parents[1]
CLI=ROOT/'runtime/forge-store.php'
def command(*args, good=True):
    r=subprocess.run(['php',str(CLI),*map(str,args)],text=True,capture_output=True)
    if good and r.returncode:raise AssertionError(r.stderr)
    if not good and not r.returncode:raise AssertionError('expected reject: '+str(args))
    return json.loads(r.stdout) if good else r.stderr

def main():
    rows=[]
    for seq,(lat,regen) in enumerate([(430,620),(780,300),(120,900)],start=1):
        rows.append(event(seq,lat,regen,rows[-1]['digest'] if rows else None))
    with tempfile.TemporaryDirectory() as td:
        store=pathlib.Path(td)/'journal'
        corpus=pathlib.Path(td)/'in.jsonl'
        corpus.write_text(''.join(canon(x)+'\n' for x in rows[:2]))
        a=command('append',corpus,store)
        assert a['new_blocks']==2 and a['stored_events']==2
        again=command('append',corpus,store)
        assert again['new_blocks']==0
        before=command('replay',store)
        assert before['result']['tetrahedra']==14
        corpus.write_text(''.join(canon(x)+'\n' for x in rows))
        a=command('append',corpus,store)
        assert a['new_blocks']==1 and a['stored_events']==3
        after=command('replay',store)
        assert after['result']['tetrahedra']==18
        assert after['result']['head']==rows[-1]['digest']
        corpus.write_text(canon(rows[0])+'\n')
        assert 'rollback' in command('append',corpus,store,good=False)
        forged=list(rows)
        forged[1] = {'body':dict(rows[1]['body']), 'digest':rows[1]['digest']}
        forged[1]['body']['lambda_milli']+=1
        corpus.write_text(''.join(canon(x)+'\n' for x in forged))
        assert 'native admission rejected' in command('append',corpus,store,good=False)
        block=store/'blocks'/(rows[1]['digest'][7:]+'.json')
        assert block.exists()
        block.chmod(0o600)
        data=block.read_bytes();block.write_bytes(data.replace(b'"seed":137',b'"seed":136'))
        assert 'semantic hash' in command('replay',store,good=False)
    print('STORE PASS: immutable block import, idempotence, append-only extension, cold replay, rollback rejection, forged event rejection, modified block rejection')
if __name__=='__main__':main()
