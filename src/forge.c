/* FORGE R0: native, schema-bound omission -> simplicial complex.
 * SPDX-License-Identifier: MIT
 * Contract: V2.1 restricted integer/ASCII JSONL, not arbitrary JSON or RFC8785.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <openssl/evp.h>

#define MAX_EVENTS 250
#define MAX_LINE 65536
#define MAX_STRANDS 17
#define HASH_SIZE 262144u
#define MAX_SIMPLICES 60000
#define DOMAIN "FORGE/OMISSION/V3\n"

typedef struct { char *s; size_t i,n; } Parser;
typedef struct {
    int64_t seq, seed, origin_x_milli,origin_strand,lambda_milli,regen_milli;
    int64_t boundary_x_milli,amplitude_milli,sim_time_ms;
    int affected[MAX_STRANDS], affected_n;
    char parent[72], digest[72];
    int parent_null;
} Omission;
typedef struct { uint32_t dim, v[4]; } Simplex;
typedef struct { Simplex *items; uint32_t n; uint32_t *hash_table; uint32_t vertex_count; } Complex;
static void die(const char *s){fprintf(stderr,"FORGE R0 ERROR: %s\n",s);exit(2);}
static void require(int b,const char *s){if(!b)die(s);}
static void ws(Parser *p){while(p->i<p->n&&(p->s[p->i]==' '||p->s[p->i]=='\t'||p->s[p->i]=='\r'))p->i++;}
static int eat(Parser *p,char c){ws(p);if(p->i<p->n&&p->s[p->i]==c){p->i++;return 1;}return 0;}
static void expect(Parser *p,char c){if(!eat(p,c))die("malformed JSON syntax");}
static void word(Parser *p,char *dst,size_t cap){
    ws(p);expect(p,'"');size_t j=0;int ended=0;
    while(p->i<p->n){unsigned char c=(unsigned char)p->s[p->i++];
        if(c=='"'){ended=1;break;}
        /* Restricted V2.1 schema only: reject escaping, control and non-ASCII. */
        require(c>=32&&c<127&&c!='\\',"unsupported JSON string escape / Unicode");
        require(j+1<cap,"JSON string too long");dst[j++]=(char)c;
    }
    require(ended,"unterminated JSON string");dst[j]=0;
}
static int64_t integer(Parser *p){
    ws(p);size_t s=p->i;
    if(p->i<p->n&&p->s[p->i]=='-')p->i++;
    require(p->i<p->n&&isdigit((unsigned char)p->s[p->i]),"expected integer");
    if(p->s[p->i]=='0'){p->i++;require(!(p->i<p->n&&isdigit((unsigned char)p->s[p->i])), "leading zero");}
    else while(p->i<p->n&&isdigit((unsigned char)p->s[p->i]))p->i++;
    size_t end=p->i;require(end-s<32,"integer too large");char tmp[32];memcpy(tmp,p->s+s,end-s);tmp[end-s]=0;
    errno=0;char *q;long long v=strtoll(tmp,&q,10);require(!errno&&*q=='\0',"invalid/overflowed integer");return (int64_t)v;
}
static int parse_null(Parser *p){ws(p);if(p->n-p->i>=4&&!memcmp(p->s+p->i,"null",4)){p->i+=4;return 1;}return 0;}
static int field(const char *s){
    static const char *names[]={"schema","kind","seq","seed","model","origin_x_milli","origin_strand","lambda_milli","regen_milli","boundary_x_milli","affected_strands","amplitude_milli","sim_time_ms","parent_hash"};
    for(int i=0;i<14;i++){if(!strcmp(s,names[i]))return i;}
    return -1;
}
static void parse_body(Parser *p,Omission *o){
    uint32_t seen=0;expect(p,'{');
    do {char key[64];word(p,key,sizeof(key));expect(p,':');int f=field(key);require(f>=0,"unknown body property");require(!(seen&(1u<<f)),"duplicate body property");seen|=1u<<f;
      switch(f){
        case 0:case 1:case 4:{char s[64];word(p,s,sizeof(s));require(!strcmp(s,f==0?"forge.omission.v3":f==1?"omission.simulated":"forge-confluence.v1"),"schema/kind/model mismatch");break;}
        case 2:o->seq=integer(p);break;
        case 3:o->seed=integer(p);break;
        case 5:o->origin_x_milli=integer(p);break;
        case 6:o->origin_strand=integer(p);break;
        case 7:o->lambda_milli=integer(p);break;
        case 8:o->regen_milli=integer(p);break;
        case 9:o->boundary_x_milli=integer(p);break;
        case 10:{expect(p,'[');o->affected_n=0;if(!eat(p,']')){do{require(o->affected_n<MAX_STRANDS,"affected list exceeds strand limit");int64_t x=integer(p);require(x>=0&&x<MAX_STRANDS,"affected strand outside domain");o->affected[o->affected_n++]=(int)x;}while(eat(p,','));expect(p,']');}break;}
        case 11:o->amplitude_milli=integer(p);break;
        case 12:o->sim_time_ms=integer(p);break;
        case 13:if(parse_null(p))o->parent_null=1;else {word(p,o->parent,sizeof(o->parent));o->parent_null=0;}break;
      }
    }while(eat(p,','));expect(p,'}');require(seen==((1u<<14)-1),"missing body property");
}
static void parse_record(const char *line,Omission *o){
    memset(o,0,sizeof(*o));Parser p={(char*)line,0,strlen(line)};expect(&p,'{');unsigned mask=0;
    do{char key[64];word(&p,key,sizeof(key));expect(&p,':');
        if(!strcmp(key,"body")){require(!(mask&1),"duplicate body");mask|=1;parse_body(&p,o);}
        else if(!strcmp(key,"digest")){require(!(mask&2),"duplicate digest");mask|=2;word(&p,o->digest,sizeof(o->digest));}
        else die("unknown record property");
    }while(eat(&p,','));expect(&p,'}');ws(&p);
    require(p.i==p.n,"trailing data after JSON object");require(mask==3,"body or digest missing");
}
static void sha256(const void *data,size_t n,char out[72]){
    unsigned char d[EVP_MAX_MD_SIZE];unsigned dlen=0;
    require(EVP_Digest(data,n,d,&dlen,EVP_sha256(),NULL)==1&&dlen==32,"SHA-256 unavailable");
    strcpy(out,"sha256:");for(unsigned i=0;i<32;i++)sprintf(out+7+i*2,"%02x",d[i]);
}
static void validate(Omission *o,int index,const char *parent){
    require(o->seq==index&&o->seed==137,"invalid sequence or seed");
    require(o->lambda_milli>=0&&o->lambda_milli<=1000&&o->regen_milli>=0&&o->regen_milli<=1000,"invalid parameter range");
    require(o->sim_time_ms>=0&&o->sim_time_ms<=1000000000000LL,"invalid simulated time");
    int strand=((index-1)*7+3)%17;
    int x=125+(((index-1)*53)%230),amp=38+((index*19)%38);
    require(o->origin_strand==strand&&o->origin_x_milli==(int64_t)x*1000,"origin does not match deterministic model");
    require(o->boundary_x_milli==o->origin_x_milli+75000+390*o->lambda_milli,"first divergence boundary mismatch");
    require(o->amplitude_milli==(int64_t)amp*1000,"amplitude mismatch");
    int j=0;for(int i=0;i<17;i++)if(abs(i-strand)<=3){require(j<o->affected_n&&o->affected[j]==i,"affected strand mismatch");j++;}
    require(j==o->affected_n,"affected strand count mismatch");
    require(index==1?o->parent_null:!o->parent_null,"invalid genesis/parent nullability");
    if(index>1)require(!strcmp(parent,o->parent),"parent hash chain mismatch");
    require(strlen(o->digest)==71&&!strncmp(o->digest,"sha256:",7),"invalid digest format");
    for(int i=7;i<71;i++)require(isxdigit((unsigned char)o->digest[i])&&!(o->digest[i]>='A'&&o->digest[i]<='F'),"digest must use lowercase hex");
    /* V2.1 body properties are ASCII identifiers and nonnegative integers.
     * Re-encoding in lexical-key order exactly matches its restricted canon(). */
    char arr[128]={0};size_t at=0;
    for(int i=0;i<o->affected_n;i++){
       int n=snprintf(arr+at,sizeof(arr)-at,"%s%d",i?",":"",o->affected[i]);
       require(n>0&&(size_t)n<sizeof(arr)-at,"affected array overflow");at+=(size_t)n;
    }
    char canonical[4096];
    int n=snprintf(canonical,sizeof(canonical),
      "{\"affected_strands\":[%s],\"amplitude_milli\":%lld,\"boundary_x_milli\":%lld,\"kind\":\"omission.simulated\",\"lambda_milli\":%lld,\"model\":\"forge-confluence.v1\",\"origin_strand\":%lld,\"origin_x_milli\":%lld,\"parent_hash\":%s,\"regen_milli\":%lld,\"schema\":\"forge.omission.v3\",\"seed\":137,\"seq\":%lld,\"sim_time_ms\":%lld}",
      arr,(long long)o->amplitude_milli,(long long)o->boundary_x_milli,(long long)o->lambda_milli,
      (long long)o->origin_strand,(long long)o->origin_x_milli,o->parent_null?"null":"\"",
      (long long)o->regen_milli,(long long)o->seq,(long long)o->sim_time_ms);
    /* parent requires insertion of its hex text between the quotes above. */
    require(n>0&&(size_t)n<sizeof(canonical),"canonical body too large");
    if(!o->parent_null){
       char *start=strstr(canonical,"\"parent_hash\":\"");require(start!=NULL,"parent placeholder missing");
       start+=strlen("\"parent_hash\":\"");
       char tmp[4096];size_t prefix=(size_t)(start-canonical);require(prefix+strlen(o->parent)+strlen(start)+2<sizeof(tmp),"parent insertion overflow");
       memcpy(tmp,canonical,prefix);tmp[prefix]=0;strcat(tmp,o->parent);strcat(tmp,"\"");strcat(tmp,start);strcpy(canonical,tmp);
    }
    char input[4200];int m=snprintf(input,sizeof(input),"%s%s",DOMAIN,canonical);
    require(m>0&&(size_t)m<sizeof(input),"digest input overflow");
    char calculated[72];sha256(input,(size_t)m,calculated);
    require(!strcmp(calculated,o->digest),"SHA-256 mismatch");
}
static uint32_t mix(uint32_t x){x^=x>>16;x*=0x7feb352du;x^=x>>15;x*=0x846ca68bu;x^=x>>16;return x;}
static uint32_t simplex_hash(const Simplex *s){uint32_t h=mix(s->dim+1);for(uint32_t i=0;i<=s->dim;i++)h=mix(h^mix(s->v[i]+11));return h&(HASH_SIZE-1);}
static void complex_init(Complex *k){memset(k,0,sizeof(*k));k->items=calloc(MAX_SIMPLICES,sizeof(Simplex));k->hash_table=calloc(HASH_SIZE,sizeof(uint32_t));require(k->items&&k->hash_table,"complex allocation failed");}
static void complex_free(Complex *k){free(k->items);free(k->hash_table);}
static void sort_vertices(uint32_t *v,int len){for(int i=1;i<len;i++){uint32_t x=v[i];int j=i;while(j>0&&v[j-1]>x){v[j]=v[j-1];j--;}v[j]=x;}}
static int get_simplex(Complex *k,const Simplex *s){uint32_t h=simplex_hash(s);while(k->hash_table[h]){
      uint32_t pos=k->hash_table[h]-1;Simplex *q=&k->items[pos];
      if(q->dim==s->dim&&!memcmp(q->v,s->v,(s->dim+1)*sizeof(uint32_t)))return (int)pos;
      h=(h+1)&(HASH_SIZE-1);
   }return -1;
}
static void add_simplex(Complex *k,int dim,const uint32_t *vertices){
    require(dim>=0&&dim<=3,"only dimensions 0..3 supported");
    Simplex s={.dim=(uint32_t)dim};memcpy(s.v,vertices,(dim+1)*sizeof(uint32_t));sort_vertices(s.v,dim+1);
    for(int i=1;i<=dim;i++)require(s.v[i]!=s.v[i-1],"degenerate simplex");
    if(get_simplex(k,&s)>=0)return;
    require(k->n<MAX_SIMPLICES,"simplicial capacity exceeded");
    uint32_t h=simplex_hash(&s);while(k->hash_table[h])h=(h+1)&(HASH_SIZE-1);
    k->items[k->n]=s;k->hash_table[h]=++k->n;
    if(dim==0){if(s.v[0]>=k->vertex_count)k->vertex_count=s.v[0]+1;return;}
    for(int skip=0;skip<=dim;skip++){
        uint32_t face[4];int w=0;
        for(int j=0;j<=dim;j++)if(j!=skip)face[w++]=s.v[j];
        add_simplex(k,dim-1,face);
    }
}
static int boundary_squared(Complex *k){
    for(uint32_t n=0;n<k->n;n++){Simplex *s=&k->items[n];if(s->dim<2)continue;
      int coeff[16]={0};int basis[16],size=0;
      for(uint32_t i=0;i<=s->dim;i++){
        Simplex f={.dim=s->dim-1};int jj=0;
        for(uint32_t j=0;j<=s->dim;j++)if(j!=i)f.v[jj++]=s->v[j];
        require(get_simplex(k,&f)>=0,"missing simplex face");
        for(uint32_t j=0;j<=f.dim;j++){
          Simplex sub={.dim=f.dim-1};int q=0;
          for(uint32_t z=0;z<=f.dim;z++)if(z!=j)sub.v[q++]=f.v[z];
          int id=get_simplex(k,&sub);require(id>=0,"missing lower-dimensional face");
          int m=0;while(m<size&&basis[m]!=id)m++;
          if(m==size){require(size<16,"boundary basis overflow");basis[size]=id;coeff[size]=0;size++;}
          coeff[m]+=((i+j)&1)?-1:1;
        }
      }
      for(int i=0;i<size;i++)if(coeff[i])return 0;
    }return 1;
}
static int64_t counts[4];
static uint32_t *dsu;
static uint32_t root(uint32_t x){while(dsu[x]!=x){dsu[x]=dsu[dsu[x]];x=dsu[x];}return x;}
static void unite(uint32_t x,uint32_t y){x=root(x);y=root(y);if(x!=y)dsu[x]=y;}
static int components(Complex *k){
    dsu=malloc(sizeof(uint32_t)*k->vertex_count);require(dsu!=NULL,"DSU allocation");
    for(uint32_t i=0;i<k->vertex_count;i++)dsu[i]=i;
    for(uint32_t i=0;i<k->n;i++){Simplex *s=&k->items[i];if(s->dim==1)unite(s->v[0],s->v[1]);}
    int n=0;for(uint32_t i=0;i<k->vertex_count;i++)if(root(i)==i)n++;free(dsu);return n;
}
static void topology_write(FILE *out,Complex *k,Omission *records,int record_count){
    /* Every derived vertex/simplex has its own domain-separated content digest.
     * Vertex digests are anchored to the parent omission digest and role.
     * Simplex digests are anchored to dimension + sorted vertex digests. */
    char (*vertex_cids)[72]=calloc(k->vertex_count,72);
    require(vertex_cids!=NULL,"vertex CID allocation failed");
    uint32_t v=0;
    for(int i=0;i<record_count;i++){
       Omission *o=&records[i];const char *roles[]={"origin","boundary","receipt"};
       for(int j=0;j<3+o->affected_n;j++){
          const char *role=j<3?roles[j]:"affected";
          int strand=j<3?-1:o->affected[j-3];
          char material[200];
          int nn=snprintf(material,sizeof(material),"FORGE/VERTEX/R0\n%s\n%s\n%d\n",o->digest,role,strand);
          require(nn>0&&(size_t)nn<sizeof(material),"vertex CID source too long");
          sha256(material,(size_t)nn,vertex_cids[v]);
          fprintf(out,"{\"kind\":\"vertex\",\"vertex\":%u,\"cid\":\"%s\",\"role\":\"%s\",\"event\":\"%s\"",v,vertex_cids[v],role,o->digest);
          if(j>=3)fprintf(out,",\"strand\":%d",strand);
          fprintf(out,"}\n");v++;
       }
    }
    require(v==k->vertex_count,"vertex indexing mismatch");
    for(uint32_t i=0;i<k->n;i++){
        Simplex *s=&k->items[i];char material[420];
        int n=snprintf(material,sizeof(material),"FORGE/SIMPLEX/R0\n%u\n",s->dim);
        require(n>0&&(size_t)n<sizeof(material),"simplex digest prefix overflow");
        size_t len=(size_t)n;
        for(uint32_t j=0;j<=s->dim;j++){
            require(s->v[j]<k->vertex_count,"bad simplex vertex reference");
            size_t z=strlen(vertex_cids[s->v[j]]);
            require(len+z+2<sizeof(material),"simplex digest material overflow");
            memcpy(material+len,vertex_cids[s->v[j]],z);len+=z;
            material[len++]='\n';material[len]=0;
        }
        char cid[72];sha256(material,len,cid);
        fprintf(out,"{\"kind\":\"simplex\",\"cid\":\"%s\",\"dimension\":%u,\"vertices\":[",cid,s->dim);
        for(uint32_t j=0;j<=s->dim;j++)fprintf(out,"%s%u",j?",":"",s->v[j]);
        fprintf(out,"],\"vertex_cids\":[");
        for(uint32_t j=0;j<=s->dim;j++)fprintf(out,"%s\"%s\"",j?",":"",vertex_cids[s->v[j]]);
        fprintf(out,"]}\n");
    }
    free(vertex_cids);
}
static void replay(FILE *in,const char *outname){
    Omission *rows=calloc(MAX_EVENTS,sizeof(Omission));require(rows!=NULL,"record allocation failed");Complex k;complex_init(&k);
    char *line=NULL;size_t cap=0;ssize_t len;int n=0;uint32_t previous_receipt=UINT32_MAX;
    while((len=getline(&line,&cap,in))!=-1){
        require(len<MAX_LINE,"JSONL line exceeds 64 KiB");
        while(len>0&&(line[len-1]=='\n'||line[len-1]=='\r'))line[--len]=0;
        if(!len)continue;
        require(n<MAX_EVENTS,"event limit exceeded");
        parse_record(line,&rows[n]);validate(&rows[n],n+1,n?rows[n-1].digest:NULL);
        uint32_t origin=k.vertex_count; /* allocate monotonic IDs */
        uint32_t boundary=origin+1,receipt=origin+2;
        /* Vertex ID allocation is explicit because recursive closure insertion can reorder. */
        uint32_t own[]={origin,boundary,receipt};for(int i=0;i<3;i++)add_simplex(&k,0,&own[i]);
        for(int i=0;i<rows[n].affected_n;i++){
            uint32_t affected=k.vertex_count;add_simplex(&k,0,&affected);
            uint32_t tet[]={origin,boundary,receipt,affected};add_simplex(&k,3,tet);
        }
        if(previous_receipt!=UINT32_MAX){uint32_t edge[]={previous_receipt,receipt};add_simplex(&k,1,edge);}
        previous_receipt=receipt;n++;
    }
    require(!ferror(in),"read error");free(line);
    require(boundary_squared(&k),"boundary^2 != 0");
    memset(counts,0,sizeof(counts));for(uint32_t i=0;i<k.n;i++)counts[k.items[i].dim]++;
    int comp=components(&k);int64_t chi=counts[0]-counts[1]+counts[2]-counts[3];
    if(outname){FILE *out=fopen(outname,"wb");require(out!=NULL,"failed to create topology output");topology_write(out,&k,rows,n);require(!ferror(out)&&fclose(out)==0,"failed writing topology output");}
    printf("{\"schema\":\"forge.kernel.r0\",\"events\":%d,\"verified\":true,\"boundary_squared_zero\":true,\"vertices\":%lld,\"edges\":%lld,\"faces\":%lld,\"tetrahedra\":%lld,\"connected_components\":%d,\"euler_characteristic\":%lld,\"head\":",n,(long long)counts[0],(long long)counts[1],(long long)counts[2],(long long)counts[3],comp,(long long)chi);
    if(n)printf("\"%s\"",rows[n-1].digest);else printf("null");puts("}");
    complex_free(&k);free(rows);
}
static void simplex_cli(const char *arg){
    uint32_t v[4]={0};int n=0;const char *p=arg;
    while(*p){require(n<4,"simplex dimension exceeds 3");errno=0;char *end;unsigned long z=strtoul(p,&end,10);require(!errno&&end!=p&&z<100000&&(*end==','||*end==0),"invalid simplex vertex argument");v[n++]=(uint32_t)z;p=(*end==',')?end+1:end;require(!(*end==','&&*p==0),"trailing comma");}
    require(n>=1,"simplex needs vertices");Complex k;complex_init(&k);add_simplex(&k,n-1,v);require(boundary_squared(&k),"boundary squared failed");
    memset(counts,0,sizeof(counts));for(uint32_t i=0;i<k.n;i++)counts[k.items[i].dim]++;
    printf("{\"schema\":\"forge.kernel.simplex\",\"dimension\":%d,\"boundary_squared_zero\":true,\"vertices\":%lld,\"edges\":%lld,\"faces\":%lld,\"tetrahedra\":%lld}\n",n-1,(long long)counts[0],(long long)counts[1],(long long)counts[2],(long long)counts[3]);complex_free(&k);
}
int main(int argc,char **argv){
    if(argc==3&&!strcmp(argv[1],"simplex")){simplex_cli(argv[2]);return 0;}
    if(argc>=3&&argc<=5&&!strcmp(argv[1],"replay")){
       const char *path=argv[2],*out=NULL;
       if(argc==5){require(!strcmp(argv[3],"--topology"),"expected --topology <path>");out=argv[4];require(strcmp(path,out)!=0,"input and topology output must be different files");}
       FILE *in=!strcmp(path,"-")?stdin:fopen(path,"rb");require(in!=NULL,"cannot open JSONL input");replay(in,out);if(in!=stdin)fclose(in);return 0;
    }
    fprintf(stderr,"Usage: %s simplex 4,1,2,3\n       %s replay events.jsonl [--topology derived.jsonl]\n",argv[0],argv[0]);return 2;
}