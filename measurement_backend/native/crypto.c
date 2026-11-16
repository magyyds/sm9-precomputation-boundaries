/* SM9 verification equation adapted from GmSSL src/sm9_sign.c,
 * Copyright 2014-2024 The GmSSL Project, Apache-2.0.
 * This adapter shares g across ALL methods and caches only Q(ID).
 * No pairing result or signature acceptance is cached.
 */
#include <gmssl/sm9.h>
#include <gmssl/mem.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "miller.h"

static void hash_id(const uint8_t *id,size_t n,uint8_t out[32]) { SM3_CTX c;sm3_init(&c);sm3_update(&c,id,n);sm3_finish(&c,out); }
typedef struct { SM9_SIGN_MASTER_KEY pub; sm9_z256_fp12_t g; } verifier;
typedef struct { uint8_t id_hash[32];SM9_Z256_TWIST_POINT q; } q_entry;
typedef struct { uint8_t id_hash[32];lab_miller_table table; } miller_entry;
size_t lab_q_size(void) { return sizeof(q_entry); }
size_t lab_verifier_size(void) { return sizeof(verifier); }
size_t lab_miller_size(void) { return sizeof(miller_entry); }

int lab_master_generate(uint8_t secret[32], uint8_t public_key[129]) {
    SM9_SIGN_MASTER_KEY k;
    if (sm9_sign_master_key_generate(&k) != 1) return 0;
    sm9_z256_to_bytes(k.ks, secret);
    int ok = sm9_z256_twist_point_to_uncompressed_octets(&k.Ppubs, public_key);
    gmssl_secure_clear(&k, sizeof(k));
    return ok == 1;
}

static int master_from_secret(SM9_SIGN_MASTER_KEY *k, const uint8_t secret[32]) {
    sm9_z256_from_bytes(k->ks, secret);
    if (sm9_z256_is_zero(k->ks) || sm9_z256_cmp(k->ks, sm9_z256_order()) >= 0) return 0;
    sm9_z256_twist_point_mul_generator(&k->Ppubs, k->ks);
    return 1;
}

/* Portable private-key serialization: 129-byte Ppubs + 65-byte ds. */
int lab_extract(const uint8_t secret[32], const char *id, size_t idlen, uint8_t out[194]) {
    SM9_SIGN_MASTER_KEY m;
    SM9_SIGN_KEY k;
    if (!id || !idlen || idlen > SM9_MAX_ID_SIZE || !master_from_secret(&m, secret)) return 0;
    int ok = sm9_sign_master_key_extract_key(&m, id, idlen, &k) == 1
        && sm9_z256_twist_point_to_uncompressed_octets(&k.Ppubs, out) == 1
        && sm9_z256_point_to_uncompressed_octets(&k.ds, out + 129) == 1;
    gmssl_secure_clear(&m, sizeof(m)); gmssl_secure_clear(&k, sizeof(k));
    return ok;
}

int lab_sign(const uint8_t key[194], const uint8_t *msg, size_t len, uint8_t out[97]) {
    SM9_SIGN_KEY k;
    SM9_SIGN_CTX ctx;
    SM9_SIGNATURE sig;
    int ok = sm9_z256_twist_point_from_uncompressed_octets(&k.Ppubs, key) == 1
        && sm9_z256_point_from_uncompressed_octets(&k.ds, key + 129) == 1;
    if (ok) {
        sm9_sign_init(&ctx); sm9_sign_update(&ctx, msg, len);
        ok = sm9_do_sign(&k, &ctx.sm3_ctx, &sig) == 1;
        if (ok) {
            sm9_z256_to_bytes(sig.h, out);
            ok = sm9_z256_point_to_uncompressed_octets(&sig.S, out + 32) == 1;
        }
    }
    gmssl_secure_clear(&k, sizeof(k));
    return ok;
}

void *lab_verifier_new(const uint8_t public_key[129]) {
    verifier *v = calloc(1, sizeof(*v));
    if (!v) return NULL;
    SM9_Z256_TWIST_POINT check;
    if (sm9_z256_twist_point_from_uncompressed_octets(&v->pub.Ppubs, public_key) != 1
        || sm9_z256_twist_point_is_at_infinity(&v->pub.Ppubs)) { free(v); return NULL; }
    sm9_z256_twist_point_mul(&check, sm9_z256_order(), &v->pub.Ppubs);
    if (!sm9_z256_twist_point_is_at_infinity(&check)) { free(v); return NULL; }
    sm9_z256_pairing(v->g, &v->pub.Ppubs, sm9_z256_generator());
    return v;
}
void lab_verifier_free(void *v) { free(v); }

static int build_point(void *ptr, const char *id, size_t idlen, void *out) {
    verifier *v = ptr;
    sm9_z256_t h;
    SM9_Z256_TWIST_POINT q;
    if (!v || !id || !idlen || idlen > SM9_MAX_ID_SIZE || !out) return 0;
    if (sm9_z256_hash1(h, id, idlen, SM9_HID_SIGN) != 1) return 0;
    sm9_z256_twist_point_mul_generator(&q, h);
    sm9_z256_twist_point_add_full(&q, &q, &v->pub.Ppubs);
    if (sm9_z256_twist_point_is_at_infinity(&q)) return 0;
    memcpy(out, &q, sizeof(q));
    return 1;
}

int lab_build(void *ptr,const char *id,size_t idlen,void *out) {
    q_entry *entry=out;
    if(!entry || !build_point(ptr,id,idlen,&entry->q))return 0;
    hash_id((const uint8_t *)id,idlen,entry->id_hash);return 1;
}

static int decode_signature(const uint8_t raw[97], SM9_SIGNATURE *sig) {
    sm9_z256_from_bytes(sig->h, raw);
    if (sm9_z256_is_zero(sig->h) || sm9_z256_cmp(sig->h, sm9_z256_order()) >= 0) return 0;
    if (sm9_z256_point_from_uncompressed_octets(&sig->S, raw + 32) != 1
        || sm9_z256_point_is_at_infinity(&sig->S)
        || sm9_z256_point_is_on_curve(&sig->S) != 1) return 0;
    SM9_Z256_POINT check;
    sm9_z256_point_mul(&check, sm9_z256_order(), &sig->S);
    return sm9_z256_point_is_at_infinity(&check);
}

int lab_build_miller(void *ptr,const char *id,size_t idlen,void *out) {
    SM9_Z256_TWIST_POINT q;
    if(!out || !build_point(ptr,id,idlen,&q))return 0;
    miller_entry *entry=out;hash_id((const uint8_t *)id,idlen,entry->id_hash);
    lab_miller_build(&entry->table,&q);return 1;
}

static int verify_internal(void *ptr, const char *id, size_t idlen, const uint8_t *msg,
               size_t len, const uint8_t raw[97], const void *cached_q, int miller) {
    verifier *v = ptr;
    SM9_SIGNATURE sig;
    SM9_Z256_TWIST_POINT q;
    SM9_SIGN_CTX ctx;
    sm9_z256_fp12_t t, u, w;
    sm9_z256_t h2;
    uint8_t wb[384], ha[64], ct1[4] = {0,0,0,1}, ct2[4] = {0,0,0,2};
    if (!v || !id || !idlen || idlen>SM9_MAX_ID_SIZE || !decode_signature(raw, &sig)) return 0;
    if(cached_q) {
        uint8_t digest[32];hash_id((const uint8_t *)id,idlen,digest);
        if(memcmp(digest,cached_q,32))return 0;
    }
    if (cached_q && !miller) memcpy(&q, &((const q_entry *)cached_q)->q, sizeof(q));
    else if(cached_q && miller) { /* The table replaces only Q-dependent work. */ }
    else if (!build_point(v, id, idlen, &q)) return 0;
    sm9_z256_fp12_pow(t, v->g, sig.h);
    if(cached_q && miller)lab_miller_pair(u,&((const miller_entry *)cached_q)->table,&sig.S);
    else sm9_z256_pairing(u, &q, &sig.S);
    sm9_z256_fp12_mul(w, u, t);
    sm9_z256_fp12_to_bytes(w, wb);
    sm9_verify_init(&ctx); sm9_verify_update(&ctx, msg, len);
    sm3_update(&ctx.sm3_ctx, wb, sizeof(wb));
    SM3_CTX second = ctx.sm3_ctx;
    sm3_update(&ctx.sm3_ctx, ct1, 4); sm3_finish(&ctx.sm3_ctx, ha);
    sm3_update(&second, ct2, 4); sm3_finish(&second, ha + 32);
    sm9_z256_modn_from_hash(h2, ha);
    return sm9_z256_equ(h2, sig.h) == 1;
}

int lab_verify(void *p,const char *id,size_t n,const uint8_t *m,size_t len,const uint8_t sig[97],const void *q) {
    return verify_internal(p,id,n,m,len,sig,q,0);
}
int lab_verify_miller(void *p,const char *id,size_t n,const uint8_t *m,size_t len,const uint8_t sig[97],const void *q) {
    return verify_internal(p,id,n,m,len,sig,q,1);
}

int lab_verify_reference(void *ptr, const char *id, size_t idlen,
                         const uint8_t *msg, size_t len, const uint8_t raw[97]) {
    verifier *v = ptr; SM9_SIGNATURE sig; SM9_SIGN_CTX ctx;
    if (!v || !decode_signature(raw, &sig)) return 0;
    sm9_verify_init(&ctx); sm9_verify_update(&ctx, msg, len);
    return sm9_do_verify(&v->pub, id, idlen, &ctx.sm3_ctx, &sig) == 1;
}
