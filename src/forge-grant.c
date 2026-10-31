/* FORGE/0 Chapter 7: fixed-format Ed25519 grant and request verification.
 * Signatures confer no standalone authority: the pinned root and the
 * PHP journal's atomic state checks remain mandatory.
 * SPDX-License-Identifier: MIT
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define MAX_DOC 4096
static void fail(const char *s){fprintf(stderr,"FORGE GRANT REJECTED: %s\n",s);exit(2);}
static void need(int truth,const char *why){if(!truth)fail(why);}
static int unhex(const char *hex,unsigned char *out,size_t n){
 if(strlen(hex)!=n*2)return 0;
 for(size_t i=0;i<n;i++){
  char a=hex[i*2],b=hex[i*2+1];
  int h=(a>='0'&&a<='9')?a-'0':(a>='a'&&a<='f')?a-'a'+10:-1;
  int l=(b>='0'&&b<='9')?b-'0':(b>='a'&&b<='f')?b-'a'+10:-1;
  if(h<0||l<0)return 0;
  out[i]=(unsigned char)(h*16+l);
 }return 1;
}
static void hexout(const unsigned char *b,size_t n,char *out){const char *d="0123456789abcdef";for(size_t i=0;i<n;i++){out[2*i]=d[b[i]>>4];out[2*i+1]=d[b[i]&15];}out[2*n]=0;}
static void digest(const char *buf,size_t len,char out[65]){unsigned char raw[32];SHA256((const unsigned char*)buf,len,raw);hexout(raw,32,out);}
static int valid_cid(const char *s){unsigned char out[32];return !strncmp(s,"sha256:",7)&&unhex(s+7,out,32);}
static int valid_key(const char *s){unsigned char out[32];return !strncmp(s,"ed25519:",8)&&unhex(s+8,out,32);}
static int valid_nonce(const char *s){unsigned char out[32];return unhex(s,out,32);}
static void edverify(const char *key,const char *sig,const char *msg,size_t len){
 unsigned char rawkey[32],rawsig[64];need(unhex(key,rawkey,32),"malformed public key");need(unhex(sig,rawsig,64),"malformed signature");
 EVP_PKEY *p=EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,NULL,rawkey,32);need(p!=NULL,"invalid Ed25519 key");
 EVP_MD_CTX *ctx=EVP_MD_CTX_new();need(ctx!=NULL,"crypto allocation failed");
 int ok=EVP_DigestVerifyInit(ctx,NULL,NULL,NULL,p)==1&&EVP_DigestVerify(ctx,rawsig,64,(const unsigned char*)msg,len)==1;
 EVP_MD_CTX_free(ctx);EVP_PKEY_free(p);need(ok,"Ed25519 signature invalid");
}
typedef struct {char buf[MAX_DOC+2];size_t used,signed_len;char *lines[16];size_t n;} Doc;
static void read_doc(const char *path,Doc *d){
 memset(d,0,sizeof(*d));FILE *f=fopen(path,"rb");need(f!=NULL,"cannot read document");
 d->used=fread(d->buf,1,MAX_DOC+1,f);need(!ferror(f),"read failed");fclose(f);
 need(d->used>0&&d->used<=MAX_DOC,"document empty or oversized");
 need(d->buf[d->used-1]=='\n',"document must terminate in newline");
 for(size_t i=0;i<d->used;i++)need(d->buf[i]!='\r'&&((unsigned char)d->buf[i]>=32||d->buf[i]=='\n'),"noncanonical control byte");
 d->buf[d->used]='\0';
 size_t start=0;for(size_t i=0;i<d->used;i++)if(d->buf[i]=='\n'){
  need(d->n<16,"too many lines");d->lines[d->n++]=d->buf+start;d->buf[i]='\0';need(i>start,"empty line forbidden");start=i+1;
 }
}
static const char *field(Doc *d,size_t index,const char *expected){
 need(index<d->n,"missing field");size_t n=strlen(expected);
 need(!strncmp(d->lines[index],expected,n),"unexpected field or field ordering");
 const char *v=d->lines[index]+n;need(*v,"empty field");return v;
}
static size_t signed_bytes(Doc *d,size_t signature_line,char out[MAX_DOC+1]){
 need(signature_line<d->n,"missing signature line");
 size_t offset=(size_t)(d->lines[signature_line]-d->buf);
 need(offset>0&&offset<d->used,"invalid signed prefix");
 /* Restore canonical line endings for the signed portion. */
 memcpy(out,d->buf,offset);
 for(size_t i=0;i<offset;i++)if(!out[i])out[i]='\n';
 out[offset]=0;
 return offset;
}
static unsigned long long number(const char *s){
 need(*s,"empty numeric field");unsigned long long x=0;
 for(const char *p=s;*p;p++){need(*p>='0'&&*p<='9',"numeric field is not canonical");need(x<=410244480000ULL/10,"numeric field overflow");x=x*10+(unsigned)(*p-'0');}
 return x;
}
int main(int argc,char **argv){
 need(argc==5&&(!strcmp(argv[1],"verify")||!strcmp(argv[1],"verify-history")),"Usage: forge-grant verify|verify-history grant.fg request.fe PINNED_ROOT_ED25519_HEX");
 Doc g,r;read_doc(argv[2],&g);read_doc(argv[3],&r);
 need(g.n==10&&!strcmp(g.lines[0],"FORGE-GRANT/1"),"unexpected grant schema");
 const char *issuer=field(&g,1,"issuer=");
 const char *subject=field(&g,2,"subject=");
 const char *scope=field(&g,3,"scope=");
 const char *target=field(&g,4,"target=");
 const char *nonce=field(&g,5,"nonce=");
 const char *start=field(&g,6,"not_before=");
 const char *end=field(&g,7,"expires_at=");
 const char *limit=field(&g,8,"limit=");
 const char *gsig=field(&g,9,"signature=");
 need(valid_key(issuer)&&valid_key(subject),"invalid grant key");
 unsigned char pinned[32],issued[32];need(unhex(argv[4],pinned,32)&&unhex(issuer+8,issued,32)&&!memcmp(pinned,issued,32),"issuer not pinned root");
 need(!strcmp(scope,"relation.assert"),"grant scope disallowed");
 need(valid_cid(target)&&valid_nonce(nonce)&&!strcmp(limit,"1"),"grant target, nonce or limit invalid");
 unsigned long long begins=number(start),expires=number(end);
 need(begins<expires,"invalid grant validity window");
 time_t now=time(NULL);need(now>=0&&(unsigned long long)now>=begins&&(unsigned long long)now<expires,"grant outside validity interval");
 char gb[MAX_DOC+1];size_t glen=signed_bytes(&g,9,gb);edverify(issuer+8,gsig,gb,glen);
 char grant_hash[65];digest(gb,glen,grant_hash);
 need(r.n==9&&!strcmp(r.lines[0],"FORGE-EFFECT/1"),"unexpected effect schema");
 const char *rid=field(&r,1,"grant=");
 const char *rsubject=field(&r,2,"subject=");
 const char *rscope=field(&r,3,"scope=");
 const char *rtarget=field(&r,4,"target=");
 const char *rnonce=field(&r,5,"nonce=");
 const char *from=field(&r,6,"from=");
 const char *to=field(&r,7,"to=");
 const char *rsig=field(&r,8,"signature=");
 need(valid_cid(rid)&&!strncmp(rid+7,grant_hash,64),"request grant ID mismatch");
 need(!strcmp(subject,rsubject)&&!strcmp(scope,rscope)&&!strcmp(target,rtarget)&&!strcmp(nonce,rnonce),"request differs from grant");
 need(valid_cid(from)&&valid_cid(to)&&strcmp(from,to),"invalid relation endpoints");
 char rb[MAX_DOC+1];size_t rlen=signed_bytes(&r,8,rb);edverify(subject+8,rsig,rb,rlen);
 char effect_hash[65];digest(rb,rlen,effect_hash);
 printf("{\"schema\":\"forge.grant.verification.v1\",\"verified\":true,\"scope\":\"relation.assert\",\"subject\":\"%s\",\"grant\":\"sha256:%s\",\"request\":\"sha256:%s\",\"nonce\":\"%s\",\"target\":\"%s\",\"from\":\"%s\",\"to\":\"%s\",\"expiry\":%llu}\n",subject,grant_hash,effect_hash,nonce,target,from,to,expires);
 return 0;
}
