/* OpenSSL is isolated in a separate shared library to avoid symbol interposition
 * with GmSSL. Public API accepts DER certificates and raw uncompressed SM2 keys. */
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

void *lab_ca_new(const uint8_t *der,size_t len) {
    const unsigned char *p=der; X509 *ca=d2i_X509(NULL,&p,(long)len);
    if(!ca || p!=der+len){X509_free(ca);return NULL;}
    X509_STORE *s=X509_STORE_new();
    if(!s || X509_STORE_add_cert(s,ca)!=1){X509_STORE_free(s);s=NULL;}
    X509_free(ca);return s;
}
void lab_ca_free(void *p){X509_STORE_free(p);}
static int64_t as_unix(const ASN1_TIME *t) {
    struct tm tm; if(ASN1_TIME_to_tm(t,&tm)!=1)return -1;
    return (int64_t)timegm(&tm);
}
int lab_cert_verify(void *store,const uint8_t *der,size_t len,int64_t now,
                    const uint8_t *id,size_t idlen,uint8_t pub[65],int64_t validity[2]) {
    if(!store || !der || len>2048 || !id)return 0;
    const unsigned char *p=der; X509 *cert=d2i_X509(NULL,&p,(long)len);
    if(!cert || p!=der+len){X509_free(cert);return 0;}
    X509_STORE_CTX *ctx=X509_STORE_CTX_new(); EVP_PKEY *key=NULL; int ok=0;
    if(!ctx || X509_STORE_CTX_init(ctx,store,cert,NULL)!=1)goto end;
    X509_VERIFY_PARAM *param=X509_STORE_CTX_get0_param(ctx);
    X509_VERIFY_PARAM_set_time(param,(time_t)now);
    X509_VERIFY_PARAM_set_flags(param,X509_V_FLAG_X509_STRICT);
    X509_VERIFY_PARAM_set_purpose(param,X509_PURPOSE_SSL_CLIENT);
    if(X509_verify_cert(ctx)!=1){ok=-100-X509_STORE_CTX_get_error(ctx);goto end;}
    unsigned char hash[32];char expected[65],actual[128];
    SHA256(id,idlen,hash);
    for(int i=0;i<32;i++)sprintf(expected+2*i,"%02x",hash[i]);
    X509_NAME *name=X509_get_subject_name(cert);
    int cn=X509_NAME_get_text_by_NID(name,NID_commonName,actual,sizeof(actual));
    int first=X509_NAME_get_index_by_NID(name,NID_commonName,-1);
    if(cn!=64 || memcmp(expected,actual,64)!=0 || X509_NAME_get_index_by_NID(name,NID_commonName,first)>=0){ok=-3;goto end;}
    key=X509_get_pubkey(cert);
    if(!key || !EVP_PKEY_is_a(key,"SM2")){ok=-4;goto end;}
    /* Provider versions may export compressed points despite the format option.
     * Coordinate parameters give a stable 65-byte wire representation. */
    BIGNUM *x=NULL,*y=NULL;
    int coords=EVP_PKEY_get_bn_param(key,OSSL_PKEY_PARAM_EC_PUB_X,&x)==1
        && EVP_PKEY_get_bn_param(key,OSSL_PKEY_PARAM_EC_PUB_Y,&y)==1
        && BN_bn2binpad(x,pub+1,32)==32 && BN_bn2binpad(y,pub+33,32)==32;
    BN_free(x);BN_free(y);
    if(!coords){ok=-5;goto end;}
    pub[0]=4;
    validity[0]=as_unix(X509_get0_notBefore(cert));validity[1]=as_unix(X509_get0_notAfter(cert));
    ok=validity[0]>=0 && validity[0]<=now && now<=validity[1];
end:
    EVP_PKEY_free(key);X509_STORE_CTX_free(ctx);X509_free(cert);return ok;
}
int lab_pem_secret(const char *path,uint8_t secret[32]) {
    FILE *f=fopen(path,"rb");if(!f)return 0;
    EVP_PKEY *key=PEM_read_PrivateKey(f,NULL,NULL,NULL);fclose(f);BIGNUM *bn=NULL;
    int ok=key && EVP_PKEY_is_a(key,"SM2") && EVP_PKEY_get_bn_param(key,OSSL_PKEY_PARAM_PRIV_KEY,&bn)==1 && BN_bn2binpad(bn,secret,32)==32;
    BN_clear_free(bn);EVP_PKEY_free(key);return ok;
}
int lab_openssl_sm2_verify(const uint8_t pub[65],const uint8_t *id,size_t idlen,const uint8_t *msg,size_t len,const uint8_t raw[64]) {
    EVP_PKEY_CTX *from=EVP_PKEY_CTX_new_from_name(NULL,"SM2",NULL);EVP_PKEY *key=NULL;
    OSSL_PARAM params[3];char group[]="SM2";
    params[0]=OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,group,0);
    params[1]=OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,(void *)pub,65);
    params[2]=OSSL_PARAM_construct_end();
    EVP_MD_CTX *md=EVP_MD_CTX_new();EVP_PKEY_CTX *pkctx=NULL;ECDSA_SIG *sig=ECDSA_SIG_new();
    unsigned char der[80],*ptr=der;int ok=0;
    if(!from||!md||!sig||EVP_PKEY_fromdata_init(from)!=1||EVP_PKEY_fromdata(from,&key,EVP_PKEY_PUBLIC_KEY,params)!=1)goto end;
    if(ECDSA_SIG_set0(sig,BN_bin2bn(raw,32,NULL),BN_bin2bn(raw+32,32,NULL))!=1)goto end;
    int n=i2d_ECDSA_SIG(sig,&ptr);
    if(n<=0||EVP_DigestVerifyInit(md,&pkctx,EVP_sm3(),NULL,key)!=1||EVP_PKEY_CTX_set1_id(pkctx,id,(int)idlen)!=1)goto end;
    ok=EVP_DigestVerify(md,der,(size_t)n,msg,len)==1;
end:
    ECDSA_SIG_free(sig);EVP_MD_CTX_free(md);EVP_PKEY_free(key);EVP_PKEY_CTX_free(from);return ok;
}
