#!/usr/bin/env python3
"""Only local proposal persistence, no new authority or effect commits."""
import json,pathlib,subprocess,tempfile,sys
ROOT=pathlib.Path(__file__).resolve().parents[1]


def command(*cmd, good=True):
    p=subprocess.run([str(x) for x in cmd],capture_output=True,text=True)
    assert (p.returncode==0)==good, (cmd,p.stderr,p.stdout)
    return json.loads(p.stdout) if good else p

def test():
    with tempfile.TemporaryDirectory() as td:
        store=pathlib.Path(td)/'store'
        fixture=ROOT/'examples/v2_1_verified.jsonl'
        php=ROOT/'runtime/forge-proposals.php'
        storecli=ROOT/'runtime/forge-store.php'
        command('php',storecli,'append',fixture,store)
        one=command('php',php,'plan',store)
        assert one['status']=='proposed' and one['new_records']==1 and not one['effect_committed']
        two=command('php',php,'plan',store)
        assert two['status']=='already-proposed' and two['new_records']==0
        assert one['proposal']==two['proposal']
        audit=command('php',php,'audit',store)
        assert audit['verified'] and audit['proposals']==1
        assert not (store/'effects/HEAD.json').exists(), 'planner must never create effect state'
        block=store/'proposals/blocks'/(one['proposal'][7:]+'.json')
        block.chmod(0o600)
        block.write_bytes(block.read_bytes().replace(b'"authorized":false',b'"authorized":true'))
        command('php',php,'audit',store,good=False)
    print('PROPOSALS PASS: content-addressed bounded plans, duplicate idempotence, cold audit, tamper rejection, no effects')
if __name__=='__main__':test()