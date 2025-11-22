#include "hash_openssl.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <vector>
#include <cstring>

// single-shot SHA256 using OpenSSL EVP (safe and uses best backend)
static void sha256_openssl(const uint8_t *data, size_t len, uint8_t out[32]) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    unsigned int outlen = 0;
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, out, &outlen);
    EVP_MD_CTX_free(ctx);
}

void open_double_sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
    uint8_t tmp[32];
    sha256_openssl(data, len, tmp);
    sha256_openssl(tmp, 32, out);
}
