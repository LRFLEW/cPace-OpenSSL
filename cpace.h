#ifndef CPACE_H
#define CPACE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

#define CPACE_PUBKEY_SIZE 32
#define CPACE_ISK_SIZE 64

int cpace_is_initialized();
int cpace_init();
void cpace_clean();

int cpace_elligator25519(unsigned char *point,
                         const unsigned char *u, int u_size);

typedef struct cpace_challenge_data_ cpace_challenge_data;
void cpace_challenge_data_free(cpace_challenge_data *challenge);

int cpace_challenge_start(unsigned char *ya, cpace_challenge_data **challenge,
                          const char *prs, size_t prs_size,
                          const unsigned char *sid, size_t sid_size,
                          const char *ci, size_t ci_size);

int cpace_respond(unsigned char *isk,
                  unsigned char *yb, const unsigned char *ya,
                  const char *prs, size_t prs_size,
                  const unsigned char *sid, size_t sid_size,
                  const char *ci, size_t ci_size);

int cpace_challenge_finish(unsigned char *isk, cpace_challenge_data *challenge,
                           const unsigned char *yb);

int cpace_random_sid(unsigned char *sid, size_t sid_size);
void cpace_cleanse(void *ptr, size_t size);

#ifdef __cplusplus
}
#endif

#endif // CPACE_H
