#!/usr/bin/env python3
"""Chapter 7: pinned Ed25519 grants, scoped subject requests, atomic nonce receipts."""
import hashlib
import json
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
KERNEL = ROOT / 'forge-grant'
STORE = ROOT / 'runtime/forge-store.php'
EFFECTS = ROOT / 'runtime/forge-effects.php'
INPUT = ROOT / 'examples/v2_1_verified.jsonl'
ROWS = [json.loads(s) for s in INPUT.read_text().splitlines() if s.strip()]

def cmd(*args, ok=True):
    p=subprocess.run([str(x) for x in args],capture_output=True,text=True)
    assert (p.returncode == 0) == ok, f'cmd failed expectation {args}: {p.stdout} {p.stderr}'
    return p

def make_keys(root, name):
    secret=root/(name+'.pem')
    public=root/(name+'.der')
    cmd('openssl','genpkey','-algorithm','ED25519','-out',secret)
    cmd('openssl','pkey','-in',secret,'-pubout','-outform','DER','-out',public)
    raw=public.read_bytes()
    assert raw.startswith(bytes.fromhex('302a300506032b6570032100')) and len(raw)==44
    return secret,raw[-32:].hex()

def sign(secret, text, where):
    unsigned=where.with_suffix('.msg')
    unsigned.write_bytes(text.encode('ascii'))
    binary=where.with_suffix('.sig')
    cmd('openssl','pkeyutl','-sign','-rawin','-inkey',secret,'-in',unsigned,'-out',binary)
    raw=binary.read_bytes()
    assert len(raw)==64
    unsigned.unlink();binary.unlink()
    return raw.hex()

def create(grant_path,request_path,issuer,subject,rootpub,subjectpub,nonce,scope='relation.assert',expiry=4102444800, target=None):
    target=target or ROWS[-1]['digest']
    g=(f'FORGE-GRANT/1\nissuer=ed25519:{rootpub}\nsubject=ed25519:{subjectpub}\n'
       f'scope={scope}\ntarget={target}\nnonce={nonce}\nnot_before=0\nexpires_at={expiry}\nlimit=1\n')
    gid='sha256:'+hashlib.sha256(g.encode('ascii')).hexdigest()
    grant_path.write_text(g+'signature='+sign(issuer,g,grant_path)+'\n')
    r=(f'FORGE-EFFECT/1\ngrant={gid}\nsubject=ed25519:{subjectpub}\n'
       f'scope={scope}\ntarget={target}\nnonce={nonce}\n'
       f'from={ROWS[0]["digest"]}\nto={ROWS[-1]["digest"]}\n')
    request_path.write_text(r+'signature='+sign(subject,r,request_path)+'\n')
    return gid

def main():
    with tempfile.TemporaryDirectory() as temp:
        d=pathlib.Path(temp)
        issuer,rootpub=make_keys(d,'issuer')
        subject,subjectpub=make_keys(d,'subject')
        grant=d/'grant.fg';request=d/'request.fe'
        nonce='9a'*32
        gid=create(grant,request,issuer,subject,rootpub,subjectpub,nonce)
        verify=json.loads(cmd(KERNEL,'verify',grant,request,rootpub).stdout)
        assert verify['grant']==gid and verify['nonce']==nonce and verify['verified']
        store=d/'journal'
        cmd('php',STORE,'append',INPUT,store)
        cmd('php',EFFECTS,'init-root',store,rootpub)
        admitted=json.loads(cmd('php',EFFECTS,'become',grant,request,store).stdout)
        assert admitted['status']=='admitted' and admitted['committed'] and admitted['seq']==1
        audit=json.loads(cmd('php',EFFECTS,'audit',store).stdout)
        assert audit['verified'] and audit['effects']==1 and audit['unique_nonces']==1
        denied=json.loads(cmd('php',EFFECTS,'become',grant,request,store,ok=False).stdout)
        assert denied['status']=='rejected' and denied['reason']=='nonce_already_consumed' and not denied['committed']
        assert json.loads(cmd('php',EFFECTS,'audit',store).stdout)['effects']==1
        # Two simultaneous attempts must never commit the same nonce twice.
        parallel_store=d/'parallel'
        cmd('php',STORE,'append',INPUT,parallel_store)
        cmd('php',EFFECTS,'init-root',parallel_store,rootpub)
        command=['php',str(EFFECTS),'become',str(grant),str(request),str(parallel_store)]
        a=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        b=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        ao,ae=a.communicate(timeout=15)
        bo,be=b.communicate(timeout=15)
        assert sorted([a.returncode,b.returncode])==[0,2],(ao,bo,ae,be)
        assert json.loads(cmd('php',EFFECTS,'audit',parallel_store).stdout)['effects']==1
        # Wrong pinned root (a valid self-signed grant is never sufficient).
        _,other=make_keys(d,'untrusted')
        root_change=json.loads(cmd('php',EFFECTS,'init-root',store,other,ok=False).stdout)
        assert root_change['status']=='rejected' and root_change['reason']=='existing_block_conflict'
        assert 'issuer not pinned root' in cmd(KERNEL,'verify',grant,request,other,ok=False).stderr
        # A changed payload cannot reuse a previous signature.
        original=request.read_text()
        request.write_text(original.replace('scope=relation.assert','scope=relation.erase'))
        cmd(KERNEL,'verify',grant,request,rootpub,ok=False)
        request.write_text(original)
        # Valid signature but expired grant must be rejected at execution.
        expired=d/'expired.fg';expired_req=d/'expired.fe'
        create(expired,expired_req,issuer,subject,rootpub,subjectpub,'ab'*32,expiry=1)
        assert 'validity interval' in cmd(KERNEL,'verify',expired,expired_req,rootpub,ok=False).stderr
        # A well-signed request for a disallowed operation is still rejected.
        bad_scope=d/'bad_scope.fg';bad_req=d/'bad_scope.fe'
        create(bad_scope,bad_req,issuer,subject,rootpub,subjectpub,'cd'*32,scope='process.execute')
        assert 'scope disallowed' in cmd(KERNEL,'verify',bad_scope,bad_req,rootpub,ok=False).stderr
        # Wrong target cannot be signed into the live journal even by the trusted root.
        old=d/'old.fg';oldreq=d/'old.fe'
        create(old,oldreq,issuer,subject,rootpub,subjectpub,'ef'*32,target=ROWS[1]['digest'])
        bad=json.loads(cmd('php',EFFECTS,'become',old,oldreq,store,ok=False).stdout)
        assert bad['reason']=='source_head_mismatch'
        # Altered committed receipt must be detected in cold audit.
        receipt=store/'effects/blocks'/(admitted['effect'][7:]+'.json')
        receipt.chmod(0o600)
        receipt.write_bytes(receipt.read_bytes().replace(b'"relation.assert"',b'"relation.erase"'))
        bad=json.loads(cmd('php',EFFECTS,'audit',store,ok=False).stdout)
        assert bad['status']=='rejected' and bad['reason'] in {'effect_hash_invalid','noncanonical_block'}
    print('GRANTS PASS: pinned Ed25519 issuer, subject signature, one nonce/one effect, signed audit, denial receipts, tamper detection')

if __name__=='__main__':main()
