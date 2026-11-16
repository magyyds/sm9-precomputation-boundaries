/* Experimental public-exponent fixed-base methods. Known algorithms, no novelty claim.
 * Include the unchanged adapter so signature checks are byte-for-byte shared. */
#include "../../native/crypto.c"

typedef struct {
    const verifier *owner;
    unsigned width, rows, scheme;
    size_t entries;
    sm9_z256_fp12_t *table;
} fixed_table;

static unsigned exp_bit(const sm9_z256_t h,unsigned b) {
    return b<256 ? (unsigned)((h[b/64]>>(b%64))&1) : 0;
}

void *lab_fixed_new(void *ptr,unsigned width,unsigned scheme) {
    if(!ptr || width<2 || width>8 || scheme>1)return NULL;
    fixed_table *t=calloc(1,sizeof(*t));if(!t)return NULL;
    t->owner=ptr;t->width=width;t->rows=(256+width-1)/width;t->scheme=scheme;
    unsigned size=1u<<width;
    t->entries=scheme ? (size_t)t->rows*size : size;
    t->table=calloc(t->entries,sizeof(sm9_z256_fp12_t));
    if(!t->table){free(t);return NULL;}
    if(!scheme) {
        sm9_z256_fp12_t basis[8];sm9_z256_fp12_copy(basis[0],t->owner->g);
        for(unsigned j=1;j<width;j++) {
            sm9_z256_fp12_copy(basis[j],basis[j-1]);
            for(unsigned k=0;k<t->rows;k++)sm9_z256_fp12_sqr(basis[j],basis[j]);
        }
        sm9_z256_fp12_set_one(t->table[0]);
        for(unsigned d=1;d<size;d++) {
            unsigned bit=0;while(!((d>>bit)&1))bit++;
            sm9_z256_fp12_mul(t->table[d],t->table[d^(1u<<bit)],basis[bit]);
        }
    } else {
        sm9_z256_fp12_t base;sm9_z256_fp12_copy(base,t->owner->g);
        for(unsigned j=0;j<t->rows;j++) {
            size_t off=(size_t)j*size;sm9_z256_fp12_set_one(t->table[off]);
            for(unsigned d=1;d<size;d++)sm9_z256_fp12_mul(t->table[off+d],t->table[off+d-1],base);
            for(unsigned k=0;k<width;k++)sm9_z256_fp12_sqr(base,base);
        }
    }
    return t;
}
void lab_fixed_free(void *ptr) { fixed_table *t=ptr;if(t){free(t->table);free(t);} }
size_t lab_fixed_bytes(void *ptr) { fixed_table *t=ptr;return t?sizeof(*t)+t->entries*sizeof(sm9_z256_fp12_t):0; }

static void fixed_pow(sm9_z256_fp12_t out,const fixed_table *t,const sm9_z256_t h) {
    sm9_z256_fp12_set_one(out);
    if(!t->scheme) {
        for(int i=(int)t->rows-1;i>=0;i--) {
            unsigned d=0;
            for(unsigned j=0;j<t->width;j++)d|=exp_bit(h,(unsigned)i+j*t->rows)<<j;
            sm9_z256_fp12_sqr(out,out);
            if(d)sm9_z256_fp12_mul(out,out,t->table[d]);
        }
    } else {
        for(unsigned i=0;i<t->rows;i++) {
            unsigned d=0;
            for(unsigned j=0;j<t->width;j++)d|=exp_bit(h,i*t->width+j)<<j;
            if(d)sm9_z256_fp12_mul(out,out,t->table[((size_t)i<<t->width)+d]);
        }
    }
}
int lab_fixed_check(void *ptr,void *tab,const uint8_t raw[32]) {
    verifier *v=ptr;fixed_table *t=tab;sm9_z256_t h;sm9_z256_fp12_t a,b;
    if(!v || !t || t->owner!=v)return 0;
    sm9_z256_from_bytes(h,raw);sm9_z256_fp12_pow(a,v->g,h);fixed_pow(b,t,h);
    return sm9_z256_fp12_equ(a,b);
}
int lab_fixed_verify(void *ptr,void *tab,const char *id,size_t idlen,
    const uint8_t *msg,size_t len,const uint8_t raw[97],const void *cached_q,int miller) {
    verifier *v=ptr;fixed_table *f=tab;SM9_SIGNATURE sig;SM9_Z256_TWIST_POINT q;
    SM9_SIGN_CTX ctx;sm9_z256_fp12_t t,u,w;sm9_z256_t h2;
    uint8_t wb[384],ha[64],ct1[4]={0,0,0,1},ct2[4]={0,0,0,2};
    if(!v || !f || f->owner!=v || !id || !idlen || idlen>SM9_MAX_ID_SIZE || !decode_signature(raw,&sig))return 0;
    if(cached_q) {
        uint8_t digest[32];hash_id((const uint8_t *)id,idlen,digest);
        if(memcmp(digest,cached_q,32))return 0;
    }
    if(cached_q && !miller)memcpy(&q,&((const q_entry *)cached_q)->q,sizeof(q));
    else if(!cached_q && !build_point(v,id,idlen,&q))return 0;
    fixed_pow(t,f,sig.h);
    if(cached_q && miller)lab_miller_pair(u,&((const miller_entry *)cached_q)->table,&sig.S);
    else sm9_z256_pairing(u,&q,&sig.S);
    sm9_z256_fp12_mul(w,u,t);sm9_z256_fp12_to_bytes(w,wb);
    sm9_verify_init(&ctx);sm9_verify_update(&ctx,msg,len);sm3_update(&ctx.sm3_ctx,wb,sizeof(wb));
    SM3_CTX second=ctx.sm3_ctx;
    sm3_update(&ctx.sm3_ctx,ct1,4);sm3_finish(&ctx.sm3_ctx,ha);
    sm3_update(&second,ct2,4);sm3_finish(&second,ha+32);
    sm9_z256_modn_from_hash(h2,ha);return sm9_z256_equ(h2,sig.h)==1;
}
