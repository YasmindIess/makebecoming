#!/usr/bin/env python3
"""Isolated HTML acceptance. This is not an HTTPS/WebCrypto deployment test."""
import hashlib
import json
from pathlib import Path
from playwright.sync_api import sync_playwright
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
ROOT=Path(__file__).resolve().parents[1]

def verify(pk,sig,body):
    try:
        Ed25519PublicKey.from_public_bytes(bytes(pk)).verify(bytes(sig),bytes(body))
        return True
    except Exception:return False

bridge=r'''
Object.defineProperty(globalThis,'crypto',{configurable:true,value:{subtle:{
 digest:async (_alg,bytes)=>Uint8Array.from(await window.__forgeHash([...new Uint8Array(bytes)])).buffer,
 importKey:async (_fmt,key)=>({raw:[...new Uint8Array(key)]}),
 verify:async (_alg,key,sig,bytes)=>window.__forgeSignature(key.raw,[...new Uint8Array(sig)],[...new Uint8Array(bytes)])
}}});
window.fetch=async path=>{
 const p=String(path).replace(/^\.\//,'');
 if(!Object.prototype.hasOwnProperty.call(window.__forgeFiles,p))return {ok:false,status:404};
 const data=window.__forgeFiles[p];return {ok:true,json:async()=>JSON.parse(data),text:async()=>data};
};
'''

def test():
    resources={str(p): (ROOT/p).read_text() for p in map(Path,[
        'minima.json','field.json','occlusion-public.json','grants/public-demo.json','examples/v2_1_verified.jsonl'])}
    with sync_playwright() as p:
        browser=p.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox','--disable-dev-shm-usage'])
        page=browser.new_page(viewport={'width':1470,'height':920})
        errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
        page.expose_function('__forgeHash',lambda b:list(hashlib.sha256(bytes(b)).digest()))
        page.expose_function('__forgeSignature',verify)
        page.evaluate('(data)=>{window.__forgeFiles=data;}',resources)
        page.evaluate(bridge)
        page.set_content((ROOT/'index.html').read_text(),wait_until='domcontentloaded')
        page.select_option('#screen','confluence')
        page.wait_for_function("document.querySelector('#confluenceStatus').textContent.includes('independently checked')",timeout=20000)
        assert page.locator('#confluenceDecision').inner_text()=='WITNESS PROPOSED · NOT AUTHORIZED'
        assert page.locator('#step').is_disabled()
        assert page.locator('#confluenceScene').is_visible()
        page.locator('#confluenceStep').fill('0')
        assert '0 /' in page.locator('#confluenceStepVal').inner_text()
        page.locator('#confluenceStep').fill('8')
        assert 'final'==page.locator('#confluenceStepVal').inner_text()
        page.select_option('#confluenceView','right')
        assert 'LEFT' in page.locator('#confluenceBasins').inner_text()
        page.select_option('#screen','grants')
        page.wait_for_function("document.querySelector('#grantStatus').textContent.includes('Ed25519 verified')",timeout=10000)
        page.select_option('#screen','occlusion')
        page.wait_for_function("document.querySelector('#occlusionStatus').textContent.includes('inverse checked')")
        page.select_option('#screen','field')
        page.wait_for_function("document.querySelector('#nativeStatus').textContent.includes('cross-checked')")
        page.select_option('#screen','omission');page.click('#step')
        page.wait_for_function("document.querySelector('#selection').textContent==='Event 1'")
        page.select_option('#screen','confluence')
        page.select_option('#confluenceView','both')
        assert page.locator('#confluenceScene').is_visible() and page.locator('#step').is_disabled()
        assert not errors,errors
        page.screenshot(path=str(ROOT/'chapter8_preview.png'),full_page=True)
        browser.close()
    print('CH8 ISOLATED BROWSER PASS: five modes, independent native model check, descent scrubber, witness remains non-authoritative')
if __name__=='__main__':test()