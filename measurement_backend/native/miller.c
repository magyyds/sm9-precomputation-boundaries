/* Loop structure adapted from GmSSL sm9_z256.c, Apache-2.0.
 * Building with formal affine coordinates (1,1) isolates coefficients:
 * lw0(Q), lw1(Q)*x(S), lw2(Q)*y(S). These coordinates are coefficient
 * placeholders, never accepted as a curve point. Each verification still
 * evaluates every line at the validated S and performs final exponentiation.
 */
#include "miller.h"
#include <string.h>
#include <assert.h>
static const char bits[]="00100000000000000000000000000000000000010000101100020200101000020";
void lab_miller_build(lab_miller_table *out,const SM9_Z256_TWIST_POINT *q) {
    SM9_Z256_TWIST_POINT t=*q,negative,q1,q2;
    SM9_Z256_AFFINE_POINT unit;
    sm9_z256_set_one(unit.X);sm9_z256_modp_to_mont(unit.X,unit.X);
    sm9_z256_copy(unit.Y,unit.X);
    sm9_z256_twist_point_neg(&negative,q);
    size_t k=0;
    for(size_t i=0;i<sizeof(bits)-1;i++) {
        sm9_z256_eval_g_tangent(&t,out->line[k++],&t,&unit);
        if(bits[i]!='0')sm9_z256_eval_g_line_no_pre(&t,out->line[k++],&t,bits[i]=='1'?q:&negative,&unit);
    }
    sm9_z256_twist_point_pi1(&q1,q);sm9_z256_twist_point_neg_pi2(&q2,q);
    sm9_z256_eval_g_line_no_pre(&t,out->line[k++],&t,&q1,&unit);
    sm9_z256_eval_g_line_no_pre(&t,out->line[k++],&t,&q2,&unit);
    assert(k==LAB_MILLER_LINES);
}
static void multiply(sm9_z256_fp12_t r,const sm9_z256_fp2_t coeff[3],const SM9_Z256_AFFINE_POINT *p) {
    sm9_z256_fp2_t line[3];sm9_z256_fp2_copy(line[0],coeff[0]);
    sm9_z256_fp2_mul_fp(line[1],coeff[1],p->X);sm9_z256_fp2_mul_fp(line[2],coeff[2],p->Y);
    sm9_z256_fp12_line_mul(r,r,line);
}
void lab_miller_pair(sm9_z256_fp12_t r,const lab_miller_table *table,const SM9_Z256_POINT *p) {
    SM9_Z256_AFFINE_POINT affine;sm9_z256_point_to_affine(&affine,p);
    sm9_z256_fp12_set_one(r);size_t k=0;
    for(size_t i=0;i<sizeof(bits)-1;i++) {
        sm9_z256_fp12_sqr(r,r);multiply(r,table->line[k++],&affine);
        if(bits[i]!='0')multiply(r,table->line[k++],&affine);
    }
    multiply(r,table->line[k++],&affine);multiply(r,table->line[k++],&affine);
    assert(k==LAB_MILLER_LINES);sm9_z256_final_exponent(r,r);
}
