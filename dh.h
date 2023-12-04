#ifndef DH_H
#define DH_H

#include <openssl/evp.h>
#include <stddef.h>

enum KeyExAlgo { DH_KEY_EX, ECDH_KEY_EX };

enum DHKeySize {
  DH_KEY_SIZE_1024_160,
  DH_KEY_SIZE_2048_224,
  DH_KEY_SIZE_2048_256
};

#ifdef __cplusplus
extern "C" {
#endif

/*
 * @param key_pair the generated key pair holder
 * @param curve_id id of the used curve (defined in openssl/obj_mac.h)
 */
void ecdh_generate_key_pair(EVP_PKEY **key_pair, int curve_id);
void dh_generate_key_pair(EVP_PKEY **key_pair, enum DHKeySize key_size);
void dh_generate_key_pair_from_peer_public_key(EVP_PKEY **key_pair,
                                               EVP_PKEY *peer_pub_key);
void dh_parse_public_key(EVP_PKEY **pub_key, const unsigned char *pub_key_buf,
                         size_t pub_key_buf_len);
void dh_generate_shared_secret(EVP_PKEY *key_pair, EVP_PKEY *peer_pub_key,
                               unsigned char **shared_secret,
                               size_t *shared_secret_len);
void extract_public_key(EVP_PKEY *key_pair, unsigned char **pub_key_buf,
                        size_t *pub_key_buf_len);

#ifdef __cplusplus
}
#endif

#endif  // DH_H
