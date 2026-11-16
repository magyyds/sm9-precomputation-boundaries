#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
size_t lab_q_size(void);size_t lab_miller_size(void);
int lab_master_generate(uint8_t *,uint8_t *);int lab_extract(const uint8_t *,const char *,size_t,uint8_t *);
int lab_sign(const uint8_t *,const uint8_t *,size_t,uint8_t *);
void *lab_verifier_new(const uint8_t *);void lab_verifier_free(void *);
int lab_build(void *,const char *,size_t,void *);int lab_build_miller(void *,const char *,size_t,void *);
int lab_verify(void *,const char *,size_t,const uint8_t *,size_t,const uint8_t *,const void *);
int lab_verify_miller(void *,const char *,size_t,const uint8_t *,size_t,const uint8_t *,const void *);
int main(void) {
    uint8_t sk[32],pk[129],key[194],sig[97],message[200]={0};char id[40]={0};
    assert(lab_master_generate(sk,pk));void *v=lab_verifier_new(pk);assert(v);
    void *q=malloc(lab_q_size()),*table=malloc(lab_miller_size());assert(q&&table);
    for(int n=0;n<32;n++) {
        id[39]=(char)n;message[0]=(uint8_t)n;
        assert(lab_extract(sk,id,sizeof(id),key));assert(lab_sign(key,message,sizeof(message),sig));
        assert(lab_build(v,id,sizeof(id),q));assert(lab_build_miller(v,id,sizeof(id),table));
        assert(lab_verify(v,id,sizeof(id),message,sizeof(message),sig,q));
        assert(lab_verify_miller(v,id,sizeof(id),message,sizeof(message),sig,table));
        message[1]^=1;assert(!lab_verify_miller(v,id,sizeof(id),message,sizeof(message),sig,table));message[1]^=1;
        id[0]^=1;assert(!lab_verify(v,id,sizeof(id),message,sizeof(message),sig,q));id[0]^=1;
    }
    free(q);free(table);lab_verifier_free(v);puts("ASan/UBSan: 32 randomized SM9 round trips passed");return 0;
}
