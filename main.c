#include <openssl/evp.h>
#include <stdio.h>

#include "dh.h"
#include "util.h"

int main() {
  printf("--- DH/ECDH ---\n");

  // -----

  // Variables
  EVP_PKEY *alice_key_pair = NULL;
  unsigned char *alice_pub_key = NULL;
  //
  EVP_PKEY *bob_key_pair = NULL;
  EVP_PKEY *bobs_peer_pub_key = NULL;
  unsigned char *bob_pub_key = NULL;
  unsigned char *bob_shared_secret = NULL;
  //
  EVP_PKEY *alices_peer_pub_key = NULL;
  unsigned char *alice_shared_secret = NULL;

  // -----

  // Generate Alice's public key
  ecdh_generate_key_pair(&alice_key_pair, NID_X9_62_prime256v1);
  // dh_generate_key_pair(&alice_key_pair, DH_KEY_SIZE_2048_256);
  if (alice_key_pair == NULL) {
    goto cleanup;
  }
  // Extract Alice's raw public key
  size_t alice_pub_key_len = 0;
  extract_public_key(alice_key_pair, &alice_pub_key, &alice_pub_key_len);
  if (alice_pub_key == NULL) {
    goto cleanup;
  }
  printf("Alice's public key: ");
  print_hex(alice_pub_key, alice_pub_key_len);

  // -----

  // Send Alice's public key to Bob
  dh_parse_public_key(&bobs_peer_pub_key, alice_pub_key, alice_pub_key_len);
  if (bobs_peer_pub_key == NULL) {
    goto cleanup;
  }
  // Generate Bob's public key using infomation from Alice's public key
  dh_generate_key_pair_from_peer_public_key(&bob_key_pair, bobs_peer_pub_key);
  if (bobs_peer_pub_key == NULL) {
    goto cleanup;
  }
  // Extract Bob's raw public key
  size_t bob_pub_key_len = 0;
  extract_public_key(bob_key_pair, &bob_pub_key, &bob_pub_key_len);
  if (bob_pub_key == NULL) {
    goto cleanup;
  }
  printf("Bob's public key: ");
  print_hex(bob_pub_key, bob_pub_key_len);
  // Bob generates shared secret
  size_t bob_shared_secret_len = 0;
  dh_generate_shared_secret(bob_key_pair, bobs_peer_pub_key, &bob_shared_secret,
                            &bob_shared_secret_len);
  if (bob_shared_secret == NULL) {
    goto cleanup;
  }
  printf("Shared secret generated by Bob: ");
  print_hex_with_delim(bob_shared_secret, bob_shared_secret_len, ":");

  // -----

  // Alice receive Bob's public key back
  dh_parse_public_key(&alices_peer_pub_key, bob_pub_key, bob_pub_key_len);
  if (alices_peer_pub_key == NULL) {
    goto cleanup;
  }
  // Alice generates the shared secret
  size_t alice_shared_secret_len = 0;
  dh_generate_shared_secret(alice_key_pair, alices_peer_pub_key,
                            &alice_shared_secret, &alice_shared_secret_len);
  if (alice_shared_secret == NULL) {
    goto cleanup;
  }
  printf("Shared secret generated by Alice: ");
  print_hex_with_delim(alice_shared_secret, alice_shared_secret_len, ":");

  // The 2 shared secrets generated by Bob and Alice should be the same

cleanup:
  OPENSSL_free(alice_shared_secret);
  EVP_PKEY_free(alices_peer_pub_key);
  //
  OPENSSL_free(bob_shared_secret);
  SAFE_DEL(bob_pub_key);
  EVP_PKEY_free(bobs_peer_pub_key);
  EVP_PKEY_free(bob_key_pair);
  //
  SAFE_DEL(alice_pub_key);
  EVP_PKEY_free(alice_key_pair);
}
