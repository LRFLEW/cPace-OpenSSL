#include "cpace.h"

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <string.h>

static EVP_PKEY_CTX *keygen_ctx = NULL;
static BIGNUM *c_p = NULL, *c_r = NULL;
static BIGNUM *c_j = NULL, *c_n = NULL;

#define E(X) do { if((X) <= 0) goto clean; } while(0)

int cpace_is_initialized() {
    return keygen_ctx != NULL;
}

int cpace_init() {
    int status = 0;
    
    if (cpace_is_initialized()) return 1;
    
    E(keygen_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL));
    E(EVP_PKEY_keygen_init(keygen_ctx));
    
    E(c_p = BN_new());
    E(c_r = BN_new());
    E(c_j = BN_new());
    E(c_n = BN_new());
    
    E(BN_lshift(c_p, BN_value_one(), 255));
    E(BN_sub_word(c_p, (BN_ULONG) 19));
    E(BN_rshift1(c_r, c_p));
    BN_set_flags(c_r, BN_FLG_CONSTTIME);
    E(BN_set_word(c_j, (BN_ULONG) 486662));
    E(BN_sub(c_n, c_p, c_j));
    status = 1;
    
clean:
    if (status <= 0) cpace_clean();
    return status;
}

void cpace_clean() {
    BN_free(c_n); c_n = NULL;
    BN_free(c_j); c_j = NULL;
    BN_free(c_r); c_r = NULL;
    BN_free(c_p); c_p = NULL;
    EVP_PKEY_CTX_free(keygen_ctx); keygen_ctx = NULL;
}

int cpace_elligator25519(unsigned char *point,
                         const unsigned char *u, int u_size) {
    int status = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *x1 = NULL, *x2 = NULL, *yy = NULL, *p = NULL;
    
    E(ctx = BN_CTX_new());
    E(x2 = BN_new());
    E(yy = BN_new());
    // Load u into x1
    E(x1 = BN_lebin2bn(u, u_size, NULL));
    
    // Take x1 = u (mod 2^255 - 19)
    E(BN_mod(x1, x1, c_p, ctx));
    // x1 = -J / (1 + Z * u^2)
    E(BN_mod_sqr(x1, x1, c_p, ctx));
    E(BN_mod_add(x1, x1, x1, c_p, ctx));
    E(BN_add(x1, x1, BN_value_one()));
    E(BN_mod_inverse(x1, x1, c_p, ctx));
    E(BN_mod_mul(x1, x1, c_n, c_p, ctx));
    // yy = y^2 = x1^3 + J * x1^2 + x1 (x2 is temp)
    E(BN_mod_sqr(yy, x1, c_p, ctx));
    E(BN_mod_mul(x2, yy, x1, c_p, ctx));
    E(BN_mod_add(x2, x2, x1, c_p, ctx));
    E(BN_mod_mul(yy, yy, c_j, c_p, ctx));
    E(BN_mod_add(yy, yy, x2, c_p, ctx));
    // Set yy to Euler's criterion to test for y's existance
    E(BN_mod_exp(yy, yy, c_r, c_p, ctx));
    // x2 = -J - x1
    E(BN_mod_sub(x2, c_n, x1, c_p, ctx));
    // return x1 if it's valid, otherwise return x2
    p = BN_is_bit_set(yy, 2) ? x2 : x1;
    E(BN_bn2lebinpad(p, point, CPACE_PUBKEY_SIZE));
    status = 1;
    
clean:
    BN_clear_free(x1);
    BN_clear_free(yy);
    BN_clear_free(x2);
    BN_CTX_free(ctx);
    return status;
}

static int derive(unsigned char *out,
                  const unsigned char *pub, EVP_PKEY *priv) {
    int status = 0;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pub_key = NULL;
    size_t retsize = CPACE_PUBKEY_SIZE;
    
    E(pub_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                            pub, CPACE_PUBKEY_SIZE));
    E(ctx = EVP_PKEY_CTX_new(priv, NULL));
    E(EVP_PKEY_derive_init(ctx));
    E(EVP_PKEY_derive_set_peer(ctx, pub_key));
    E(EVP_PKEY_derive(ctx, out, &retsize));
    status = (retsize == CPACE_PUBKEY_SIZE);
    
clean:
    EVP_PKEY_CTX_free(ctx);
    return status;
}
//iferr(EVP_PKEY_keygen(pctx, &x), "keygen x");

#define H_block_SHA512 128
#define DSI1 "CPace25519-1"
#define DSI1_size (sizeof(DSI1) - 1)
#define PRS_pad (H_block_SHA512 - DSI1_size)
static const unsigned char zpad[PRS_pad];

static int map_to_group(unsigned char *point,
                        const char *prs, size_t prs_size,
                        const unsigned char *sid, size_t sid_size,
                        const char *ci, size_t ci_size) {
    unsigned char md[64];
    int status = 0;
    EVP_MD_CTX *ctx = NULL;
    const EVP_MD *md_alg = EVP_sha512();
    
    if (EVP_MD_size(md_alg) != sizeof(md)) return 0;
    
    E(ctx = EVP_MD_CTX_new());
    E(EVP_DigestInit_ex(ctx, md_alg, NULL));
    E(EVP_DigestUpdate(ctx, DSI1, DSI1_size));
    E(EVP_DigestUpdate(ctx, prs, prs_size));
    if (prs_size < PRS_pad)
        E(EVP_DigestUpdate(ctx, zpad, PRS_pad - prs_size));
    E(EVP_DigestUpdate(ctx, sid, sid_size));
    E(EVP_DigestUpdate(ctx, ci, ci_size));
    E(EVP_DigestFinal_ex(ctx, md, NULL));
    
    E(cpace_elligator25519(point, md, sizeof(md)));
    status = 1;
    
clean:
    EVP_MD_CTX_free(ctx);
    return status;
}

#define DSI2 "CPace25519-2"
#define DSI2_size (sizeof(DSI2) - 1)

static int final_keying(unsigned char *isk, const unsigned char *k,
                        const unsigned char *ya, const unsigned char *yb,
                        const unsigned char *sid, size_t sid_size) {
    int status = 0;
    EVP_MD_CTX *ctx = NULL;
    const EVP_MD *md_alg = EVP_sha512();
    
    if (EVP_MD_size(md_alg) != CPACE_ISK_SIZE) return 0;
    
    E(ctx = EVP_MD_CTX_new());
    E(EVP_DigestInit_ex(ctx, EVP_sha512(), NULL));
    E(EVP_DigestUpdate(ctx, DSI2, DSI2_size));
    E(EVP_DigestUpdate(ctx, sid, sid_size));
    E(EVP_DigestUpdate(ctx, k, CPACE_PUBKEY_SIZE));
    E(EVP_DigestUpdate(ctx, ya, CPACE_PUBKEY_SIZE));
    E(EVP_DigestUpdate(ctx, yb, CPACE_PUBKEY_SIZE));
    E(EVP_DigestFinal_ex(ctx, isk, NULL));
    status = 1;
    
clean:
    EVP_MD_CTX_free(ctx);
    return status;
}

struct cpace_challenge_data_ {
    EVP_PKEY *pkey;
    unsigned char *sid;
    size_t sid_size;
    unsigned char ya[CPACE_PUBKEY_SIZE];
};

void cpace_challenge_data_free(cpace_challenge_data *challenge) {
    if (challenge) {
        EVP_PKEY_free(challenge->pkey);
        OPENSSL_free(challenge->sid);
    }
    OPENSSL_free(challenge);
}

int cpace_challenge_start(unsigned char *ya, cpace_challenge_data **challenge,
                          const char *prs, size_t prs_size,
                          const unsigned char *sid, size_t sid_size,
                          const char *ci, size_t ci_size) {
    unsigned char g[CPACE_PUBKEY_SIZE];
    int status = 0;
    cpace_challenge_data *data = NULL;
    
    E(data = OPENSSL_malloc(sizeof(cpace_challenge_data)));
    data->pkey = NULL;
    E(data->sid = OPENSSL_malloc(sid_size));
    data->sid_size = sid_size;
    
    E(map_to_group(g, prs, prs_size, sid, sid_size, ci, ci_size));
    E(EVP_PKEY_keygen(keygen_ctx, &data->pkey));
    E(derive(data->ya, g, data->pkey));
    
    memcpy(data->sid, sid, sid_size);
    memcpy(ya, data->ya, CPACE_PUBKEY_SIZE);
    *challenge = data;
    status = 1;
    
clean:
    if (status <= 0) cpace_challenge_data_free(data);
    OPENSSL_cleanse(g, CPACE_PUBKEY_SIZE);
    return status;
}

int cpace_respond(unsigned char *isk,
                  unsigned char *yb, const unsigned char *ya,
                  const char *prs, size_t prs_size,
                  const unsigned char *sid, size_t sid_size,
                  const char *ci, size_t ci_size) {
    unsigned char g[CPACE_PUBKEY_SIZE];
    unsigned char k[CPACE_PUBKEY_SIZE];
    int status = 0;
    EVP_PKEY *pkey = NULL;
    
    E(map_to_group(g, prs, prs_size, sid, sid_size, ci, ci_size));
    E(EVP_PKEY_keygen(keygen_ctx, &pkey));
    E(derive(yb, g, pkey));
    
    E(derive(k, ya, pkey));
    E(final_keying(isk, k, ya, yb, sid, sid_size));
    status = 1;
    
clean:
    EVP_PKEY_free(pkey);
    OPENSSL_cleanse(g, CPACE_PUBKEY_SIZE);
    OPENSSL_cleanse(k, CPACE_PUBKEY_SIZE);
    return status;
}

int cpace_challenge_finish(unsigned char *isk, cpace_challenge_data *challenge,
                           const unsigned char *yb) {
    unsigned char k[CPACE_PUBKEY_SIZE];
    int status = 0;
    
    E(derive(k, yb, challenge->pkey));
    E(final_keying(isk, k, challenge->ya, yb,
                   challenge->sid, challenge->sid_size));
    status = 1;
    
clean:
    OPENSSL_cleanse(k, CPACE_PUBKEY_SIZE);
    return status;
}

int cpace_random_sid(unsigned char *sid, size_t sid_size) {
    return RAND_bytes(sid, sid_size);
}

void cpace_cleanse(void *ptr, size_t size) {
    OPENSSL_cleanse(ptr, size);
}
