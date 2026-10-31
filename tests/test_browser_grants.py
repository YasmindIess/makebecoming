#!/usr/bin/env python3
"""UI acceptance with an isolated browser harness (network navigation prohibited).

The test bridges Python cryptography into the isolated document. Real signature
verification is separately tested by the native C verifier. This is *not*
claimed as HTTPS/WebCrypto end-to-end acceptance.
"""
import hashlib
import json
import pathlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from playwright.sync_api import sync_playwright
ROOT=pathlib.Path(__file__).resolve().parents[1]

def sign_verify(public,sig,data):
    try:
        Ed25519PublicKey.from_public_bytes(bytes(public)).verify(bytes(sig),bytes(data))
        return True
    except Exception:
        return False

async_js=r'''
const output = Object.create(null);
output.subtle = {
  digest: async (_alg,bytes) => Uint8Array.from(await window.__forgeHash([...new Uint8Array(bytes)])).buffer,
  importKey: async (_fmt,key) => ({raw:[...new Uint8Array(key)]}),
  verify: async (_alg,key,sig,bytes) => window.__forgeSignature(key.raw,[...new Uint8Array(sig)],[...new Uint8Array(bytes)])
};
Object.defineProperty(globalThis,'crypto',{configurable:true,value:output});
window.fetch = async path => {
 const p=String(path).replace(/^\.\//,'');
 if(!Object.prototype.hasOwnProperty.call(window.__forgeFiles,p))return {ok:false,status:404};
 const data=window.__forgeFiles[p];
 return {ok:true,json:async()=>JSON.parse(data),text:async()=>data};
};
'''

def main():
    files={p: (ROOT/p).read_text(encoding='utf8') for p in ['grants/public-demo.json','field.json','occlusion-public.json','examples/v2_1_verified.jsonl']}
    with sync_playwright() as p:
        browser=p.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox','--disable-dev-shm-usage'])
        page=browser.new_page(viewport={'width':1440,'height':900})
        errors=[]
        page.on('pageerror',lambda error:errors.append(str(error)))
        page.expose_function('__forgeHash',lambda raw:list(hashlib.sha256(bytes(raw)).digest()))
        page.expose_function('__forgeSignature',sign_verify)
        page.evaluate('(files) => {window.__forgeFiles=files;}',files)
        page.evaluate(async_js)
        page.set_content((ROOT/'index.html').read_text(encoding='utf8'),wait_until='domcontentloaded')
        page.select_option('#screen','grants')
        page.wait_for_function("document.querySelector('#grantStatus').textContent.includes('Ed25519 verified')",timeout=20000)
        assert page.locator('#grantDecision').inner_text().startswith('ADMITTED')
        for scenario, expected in [('spent','nonce_already_consumed'),('tamper','Ed25519 verification rejects'),('wrongroot','issuer_not_pinned'),('wrongscope','scope_disallowed')]:
            page.select_option('#grantScenario',scenario)
            page.wait_for_function("(expected) => document.querySelector('#grantDecision').textContent.startsWith('REJECTED') && document.querySelector('#grantReason').textContent.includes(expected)",arg=expected)
            assert expected in page.locator('#grantReason').inner_text(),scenario
        page.select_option('#grantScenario','accepted')
        page.wait_for_function("document.querySelector('#grantDecision').textContent.startsWith('ADMITTED')")
        page.select_option('#screen','field')
        page.wait_for_function("document.querySelector('#nativeStatus').textContent.includes('cross-checked')")
        page.select_option('#screen','occlusion')
        page.wait_for_function("document.querySelector('#occlusionStatus').textContent.includes('inverse checked')")
        page.select_option('#screen','omission')
        page.click('#step')
        page.wait_for_function("document.querySelector('#selection').textContent==='Event 1'")
        page.select_option('#screen','grants')
        assert page.locator('#grantScene').is_visible()
        assert page.locator('#step').is_disabled(), 'Non-omission modes must not bypass grant boundaries'
        assert not errors,errors
        page.screenshot(path=str(ROOT/'chapter7_preview.png'),full_page=True)
        browser.close()
    print('ISOLATED BROWSER PASS: four modes + signed fixture and rejection scenarios; cryptography bridged for restricted navigation')

if __name__=='__main__':main()
