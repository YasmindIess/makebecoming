#!/usr/bin/env python3
"""Generate public DEMO-ONLY signed fixture. The private keys are never copied out."""
import json
import pathlib
import tempfile
from test_grants import ROOT,INPUT,ROWS,cmd,make_keys,create

def main():
    with tempfile.TemporaryDirectory() as t:
        d=pathlib.Path(t)
        issuer,root=make_keys(d,'demo_root')
        signer,subject=make_keys(d,'demo_subject')
        grant=d/'grant.fg';request=d/'request.fe'
        create(grant,request,issuer,signer,root,subject,'7c'*32)
        native=json.loads(cmd(ROOT/'forge-grant','verify',grant,request,root).stdout)
        store=d/'journal'
        cmd('php',ROOT/'runtime/forge-store.php','append',INPUT,store)
        cmd('php',ROOT/'runtime/forge-effects.php','init-root',store,root)
        receipt=json.loads(cmd('php',ROOT/'runtime/forge-effects.php','become',grant,request,store).stdout)
        audit=json.loads(cmd('php',ROOT/'runtime/forge-effects.php','audit',store).stdout)
        public={
           'schema':'forge.grant.public-demo.v1',
           'claim_class':'signed-test-fixture',
           'not_authority_for_public_site':True,
           'pinned_root':root,
           'grant_text':grant.read_text(),
           'request_text':request.read_text(),
           'native_verification':native,
           'committed_receipt':receipt,
           'native_audit':audit,
           'source_event_ids':[r['digest'] for r in ROWS],
           'limitations':'Demonstration-only keys, no browser grants, no persistent Vercel executor, no consensus, no token or external effects.'
        }
        out=ROOT/'grants/public-demo.json'
        out.write_text(json.dumps(public,sort_keys=True,separators=(',',':'))+'\n')
        print('Generated signed public fixture:',out.name,'root',root[:12], 'effect',receipt['effect'][:22])
if __name__=='__main__':main()
