#include "cpace.h"

#include <stdio.h>
#include <string.h>

#define STRING2(X) #X
#define STRING(X) STRING2(X)

#define MAX_PASSPHRASE_SIZE 64
#define SID_SIZE 16
#define BYTES_PER_LINE 16

#define IDENTITY_A "PartyA"
#define IDENTITY_B "PartyB"
#define IDENTITY_AB "Test"
#define CI (IDENTITY_A IDENTITY_B IDENTITY_AB)

static void print_bytes(unsigned char *buffer, size_t size, size_t breaks) {
    for (size_t i = 0; i < size; ++i) {
        if (i == 0)
            printf("%02X", buffer[i]);
        else if (breaks > 0 && i % breaks == 0)
            printf(":\n%02X", buffer[i]);
        else
            printf(":%02X", buffer[i]);
    }
}

#define E(X) do { if ((X) <= 0) { error_line = __LINE__; goto error; } } while (0)

int main(int argc, char *argv[]) {
    char prs[MAX_PASSPHRASE_SIZE + 1];
    size_t prs_size;
    unsigned char sid[SID_SIZE];
    unsigned char ya[CPACE_PUBKEY_SIZE];
    unsigned char yb[CPACE_PUBKEY_SIZE];
    unsigned char a_isk[CPACE_ISK_SIZE];
    unsigned char b_isk[CPACE_ISK_SIZE];
    cpace_challenge_data *challenge = NULL;
    int match, error_line;
    
    printf("Enter a passphrase: ");
    fflush(stdout);
    E(scanf("%" STRING(MAX_PASSPHRASE_SIZE) "s", prs));
    prs_size = strlen(prs);
    E(cpace_random_sid(sid, SID_SIZE));
    
    printf("\npassphrase: %s\n", prs);
    printf("sid: ");
    print_bytes(sid, SID_SIZE, 0);
    printf("\nci: %s\n", CI);
    
    // Initialize the cPace constants
    E(cpace_init());
    
    // Challenger initializes the protocol
    E(cpace_challenge_start(ya, &challenge, prs, prs_size,
                            sid, SID_SIZE, CI, sizeof(CI) - 1));
    printf("\nChallenger's public share:\n");
    print_bytes(ya, CPACE_PUBKEY_SIZE, BYTES_PER_LINE);
    printf("\n");
    
    // Responder responds to the challenge
    E(cpace_respond(b_isk, yb, ya, prs, prs_size,
                    sid, SID_SIZE, CI, sizeof(CI) - 1));
    printf("Responder's public share:\n");
    print_bytes(yb, CPACE_PUBKEY_SIZE, BYTES_PER_LINE);
    printf("\n");
    
    // Challenger finishes the protocol with the response data
    E(cpace_challenge_finish(a_isk, challenge, yb));
    
    // Cleanup Challenger state data
    cpace_challenge_data_free(challenge);
    
    // Cleanup the cPace constants
    cpace_clean();
    
    printf("\nChallenger's ISK: \n");
    print_bytes(a_isk, CPACE_ISK_SIZE, BYTES_PER_LINE);
    printf("\nResponder's ISK: \n");
    print_bytes(b_isk, CPACE_ISK_SIZE, BYTES_PER_LINE);
    match = memcmp(a_isk, b_isk, CPACE_ISK_SIZE) == 0;
    printf("\nISK's match: %s\n", match ? "TRUE" : "FALSE");
    
    // Cleanup the ISK for security (done for demonstration)
    cpace_cleanse(a_isk, CPACE_ISK_SIZE);
    cpace_cleanse(b_isk, CPACE_ISK_SIZE);
    
    return 0;
error:
    printf("\nERROR performing the cPace procedure on line %d\n", error_line);
    cpace_challenge_data_free(challenge);
    // Cleanup the ISK for security (done for demonstration)
    cpace_cleanse(a_isk, CPACE_ISK_SIZE);
    cpace_cleanse(b_isk, CPACE_ISK_SIZE);
    cpace_clean();
    return 1;
}
