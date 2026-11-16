#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/mem.h>
#include <string.h>

int lab_sm2_generate(uint8_t secret[32], uint8_t public_key[65]) {
    SM2_KEY key;
    if (sm2_key_generate(&key)!=1) return 0;
    sm2_z256_to_bytes(key.private_key,secret);
    int ok=sm2_z256_point_to_uncompressed_octets(&key.public_key,public_key)==1;
    gmssl_secure_clear(&key,sizeof(key)); return ok;
}
static int digest(const SM2_KEY *key,const char *id,size_t idlen,const uint8_t *msg,size_t len,uint8_t out[32]) {
    uint8_t z[32]; SM3_CTX ctx;
    if (!id || !idlen || idlen>8191 || sm2_compute_z(z,&key->public_key,id,idlen)!=1) return 0;
    sm3_init(&ctx); sm3_update(&ctx,z,32); sm3_update(&ctx,msg,len); sm3_finish(&ctx,out); return 1;
}
int lab_sm2_sign(const uint8_t secret[32],const char *id,size_t idlen,const uint8_t *msg,size_t len,uint8_t raw[64]) {
    sm2_z256_t d; SM2_KEY key; SM2_SIGNATURE sig; uint8_t dgst[32];
    sm2_z256_from_bytes(d,secret);
    if (sm2_key_set_private_key(&key,d)!=1) return 0;
    int ok=digest(&key,id,idlen,msg,len,dgst) && sm2_do_sign(&key,dgst,&sig)==1;
    if(ok){memcpy(raw,sig.r,32);memcpy(raw+32,sig.s,32);}
    gmssl_secure_clear(d,sizeof(d));gmssl_secure_clear(&key,sizeof(key));return ok;
}
int lab_sm2_verify(const uint8_t pub[65],const char *id,size_t idlen,const uint8_t *msg,size_t len,const uint8_t raw[64]) {
    SM2_KEY key; SM2_SIGNATURE sig; uint8_t dgst[32]; memset(&key,0,sizeof(key));
    if(sm2_z256_point_from_octets(&key.public_key,pub,65)!=1) return 0;
    memcpy(sig.r,raw,32);memcpy(sig.s,raw+32,32);
    return digest(&key,id,idlen,msg,len,dgst) && sm2_do_verify(&key,dgst,&sig)==1;
}
