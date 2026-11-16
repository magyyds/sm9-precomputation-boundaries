/* Measurement-only adapter: build Miller material from an already available Q.
 * Existing verifier and cryptographic implementation are not modified. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <gmssl/sm9.h>
#include "../../native/miller.h"
typedef struct { uint8_t id_hash[32]; SM9_Z256_TWIST_POINT q; } screen_q;
typedef struct { uint8_t id_hash[32]; lab_miller_table table; } screen_table;
size_t screen_q_size(void) { return sizeof(screen_q); }
size_t screen_table_size(void) { return sizeof(screen_table); }
void screen_from_q(const void *source, void *destination) {
    const screen_q *q = source;
    screen_table *t = destination;
    memcpy(t->id_hash, q->id_hash, 32);
    lab_miller_build(&t->table, &q->q);
}
