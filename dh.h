#ifndef DH_H
#define DH_H

#include <stddef.h>
#include <openssl/evp.h>

void ecdh_generate_key_pair(EVP_PKEY **key_pair);
void dh_generate_key_pair_from_peer_publib_key(EVP_PKEY ** key_pair, EVP_PKEY *peer_pub_key);
void dh_parse_public_key(EVP_PKEY **pub_key, unsigned char *pub_key_buf, size_t pub_key_buf_len);
void dh_generate_shared_secret(EVP_PKEY *key_pair, EVP_PKEY *peer_pub_key,
    unsigned char **shared_secret, size_t *shared_secret_len);
void extract_public_key(EVP_PKEY *key_pair, unsigned char **pub_key_buf, size_t *pub_key_buf_len);

#endif // DH_H
