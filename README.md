# cPace-OpenSSL
A C implementation of cPace that uses OpenSSL as the crypto library.

This library implements the **CPACE-X25519-ELLIGATOR2_SHA512-SHA512** ciphersuite for cPace using OpenSSL for its implementation of SHA512, X25519, and BIGNUM.

The cPace specification refers to the two parties as Party A and Party B. However, these names can make following the protocol a little more difficult. The API uses a different naming scheme for the parties of the protocol. Party A, who initiates the protocol, is known in the API as the Challenger, and Party B, who waits for the other party's public share, is known as the Responder. Their actions in the API are called "challenge" and "response" respectively.

This implementation **SHOULD NOT** be used in any security-critical scenarios. The implementation of cPace here, particularly the implementation of Elligator 2, is not well protected against side-channel attacks when using OpenSSL. This is primarily due to problems with the implementation of BIGNUM in OpenSSL, namely [openssl/openssl#6078](https://github.com/openssl/openssl/issues/6078) and [openssl/openssl#6640](https://github.com/openssl/openssl/issues/6640). Using BoringSSL improves timing attack resilience, but it's still not recommended to use this library when security against side-channel attacks are a priority.

There are other implementations of cPace out there, such as [jedisct1/cpace](https://github.com/jedisct1/cpace), but those implementations don't use either of the draft specification's ciphersuites and instead implement their own using Ristretto255. This implementation follows the draft specification's definition for the X25519 ciphersuite.

The specification version of cPace implemented is [draft-irtf-cfrg-cpace-00](https://tools.ietf.org/html/draft-irtf-cfrg-cpace-00)

## Example

[test.c](https://github.com/LRFLEW/cPace-OpenSSL/blob/main/test.c) includes a short command-line program to demonstrate how the API can be used. Below is a sample output of the program:

```
Enter a passphrase: hunter2

passphrase: hunter2
sid: EB:08:F6:30:19:C1:08:F0:89:02:17:82:EC:86:9C:33
ci: PartyAPartyBTest

Challenger's public share:
0D:0E:1E:35:A1:F3:28:49:72:34:A3:1F:CE:DE:C0:68:
FA:D6:44:54:81:FC:51:D0:42:B2:F6:EC:9C:64:AF:5E
Responder's public share:
49:98:D7:39:AC:9F:EC:54:1D:92:23:8C:5A:C9:D3:34:
8F:75:1B:1B:8B:31:31:B0:11:72:84:E6:F1:DF:67:3D

Challenger's ISK: 
93:F4:0F:5C:E9:F3:22:11:EB:4C:AE:05:85:64:A2:2D:
98:74:AE:B3:A8:C9:81:31:F2:77:75:8D:E6:13:B6:24:
F3:EF:DC:A3:B6:24:30:07:FF:F2:FF:EA:FF:89:4C:00:
EE:93:AD:0E:79:33:52:B2:FA:26:07:74:4D:83:8A:18
Responder's ISK: 
93:F4:0F:5C:E9:F3:22:11:EB:4C:AE:05:85:64:A2:2D:
98:74:AE:B3:A8:C9:81:31:F2:77:75:8D:E6:13:B6:24:
F3:EF:DC:A3:B6:24:30:07:FF:F2:FF:EA:FF:89:4C:00:
EE:93:AD:0E:79:33:52:B2:FA:26:07:74:4D:83:8A:18
ISK's match: TRUE
```

## API

The API header is [cpace.h](https://github.com/LRFLEW/cPace-OpenSSL/blob/main/cpace.h). All the return values in the API follow OpenSSL's return code system, where `1` indicates success and `0` indicates an error occurred.

### `#define CPACE_PUBKEY_SIZE 32`
### `#define CPACE_ISK_SIZE 64`

Macros for the size in bytes required for Ya/Yb and the ISK respectively. Any buffers used for these variables should be at least as big as these values specify.

### `int cpace_init()`

Initializes global constants utilized by Elligator 2 and private key generation. This function **must** be called before calling any other functions in this API unless otherwise specified, and should be called once at the start of the program.

### `void cpace_clean()`

Cleans the global constants that are initialized by `cpace_init()`. It is safe to call `cpace_init()` when it's already initialized and to call `cpace_clean()` when it's uninitialized or already cleaned. However, there is no reference counting in the API, so calling `cpace_clean()` will clean up the global constants independent to the number of calls made to `cpace_init()`. Because of this, it's recommended to only call these functions once each in the lifetime of your program.

### `int cpace_is_initialized()`

Returns `1` if the global constants are initialized and `0` if it is uninitialized or cleaned. This function may be called at any time.

### `int cpace_elligator25519();`

**Args:**
`unsigned char *point` **Return Arg**: The u-coordinate of the point generated by Elligator 2
`const unsigned char *u`: The input value for Elligator 2 in little-endian
`int u_size`: The size in bytes of `u`

Receives a little-endian value `u` with a size of `u_size` bytes, takes the value `u (mod 2^255 - 19)`, and returns the u-coordinate of Elligator 2's output in the buffer `point`. `point` must be at least `CPACE_PUBKEY_SIZE` bytes in size.

### `typedef struct cpace_challenge_data_ cpace_challenge_data;`

An opaque structure used to store data while Party A (the Challenger) is awaiting a response from Party B (the Responder).

### `void cpace_challenge_data_free()`

**Args:**
`cpace_challenge_data *challenge`: The pointer the challenge data to free

Deallocates the challenge data created by `cpace_challenge_start()`. This should be called when the challenge data is no longer required, either after a successful or failed call to `cpace_challenge_finish()` or after a timeout occurs waiting for a response. Setting `challenge` to `NULL` results in no operation being performed.

### `int cpace_challenge_start()`

**Args:**
`unsigned char *ya` **Return Arg**: The Challenger's public share
`cpace_challenge_data **challenge` **Return Arg**: The challenge data required by `cpace_challenge_finish()`
`const char *prs`: The Password Related String (password/passphrase)
`size_t prs_size`: The size of the PRS in bytes
`const unsigned char *sid`: The Session ID
`size_t sid_size`: The size of the SID in bytes
`const char *ci`: The CI string, formed as the concatenation of identities and optional additional data
`size_t ci_size`: The size of the CI string in bytes

Initializes the protocol as Party A (the Challenger) with the provided data. The value `ya` shall be sent to other party, while the challenge data `*challenge` is kept until a response is received. If an error occurs and the function returns `0`, then `*challenge` will be uninitialized and does not require freeing.

### `int cpace_respond()`

**Args:**
`unsigned char *isk` **Return Arg**: The Intermediate Session Key (final output of cPace)
`unsigned char *yb` **Return Arg**: The Responder's public share
`const unsigned char *ya`: The Challenger's public share
`const char *prs`: The Password Related String (password/passphrase)
`size_t prs_size`: The size of the PRS in bytes
`const unsigned char *sid`: The Session ID
`size_t sid_size`: The size of the SID in bytes
`const char *ci`: The CI string, formed as the concatenation of identities and optional additional data
`size_t ci_size`: The size of the CI string in bytes

Performs the protocol as Party B (the Challenger) with the other party's public share and the provided data. The value `yb` shall be sent to the other party, while the value `isk` is kept for encryption/authentication with the other party. It is recommended to call `cpace_cleanse()` with `isk` when you are done with its value.

### `int cpace_challenge_finish()`

**Args:**
`unsigned char *isk` **Return Arg**: The Intermediate Session Key (final output of cPace)
`cpace_challenge_data *challenge`: The challenge data from by `cpace_challenge_start()`
`const unsigned char *yb`: The Responder's public share

Performs the final steps as Party A (the Challenger) to get the final value `isk`. The value is used for encryption/authentication with the other party. It is recommended to call `cpace_cleanse()` with `isk` when you are done with its value.

### `int cpace_random_sid();`

**Args:**
`unsigned char *sid` **Return Arg**: The randomly generated SID
`size_t sid_size`: The size of the SID value in bytes to generate

A simple wrapper for OpenSSL's `RAND_bytes` provided as an option for generating a SID. The SID does *not* need to be generated this way. The standard specifies that "sid is typically pre-established by a higher-level protocol invoking CPace." This method may be used of no such higher-level session ID is available. This function may be called at any time.

### `void cpace_cleanse()`

**Args:**
`void *ptr`: The buffer to cleanse
`size_t size`: The size of the buffer in bytes

A simple wrapper for OpenSSL's `OPENSSL_cleanse`, which writes zero bytes to the provided buffer. This prevents the zero-fill from being optimized out (which can happen if directly calling `memset`). This function may be called at any time.
