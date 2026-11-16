/* Fixed-Q line coefficients for the pinned GmSSL SM9 optimal-Ate loop. */
#ifndef SIAP_MILLER_H
#define SIAP_MILLER_H
#include <gmssl/sm9.h>
enum { LAB_MILLER_LINES=77 };
typedef struct { sm9_z256_fp2_t line[LAB_MILLER_LINES][3]; } lab_miller_table;
void lab_miller_build(lab_miller_table *out,const SM9_Z256_TWIST_POINT *q);
void lab_miller_pair(sm9_z256_fp12_t out,const lab_miller_table *table,const SM9_Z256_POINT *p);
#endif
