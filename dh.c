#include "dh.h"

#include <string.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/x509.h>

void handle_errors()
{
    int e = ERR_get_error();
    printf("%s\n", ERR_error_string(e, NULL));
}

void ecdh_generate_key_pair(EVP_PKEY **key_pair, int curve_id)
{
    EVP_PKEY_CTX *params_ctx;
    EVP_PKEY *params = NULL;
    EVP_PKEY_CTX *ecdh_ctx;

    // Create parameter context for later actual parameter generation
    if (NULL == (params_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)))
    {
        handle_errors();
        goto cleanup;
    }
    if (1 != EVP_PKEY_paramgen_init(params_ctx))
    {
        handle_errors();
        goto cleanup;
    }
    if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(params_ctx, curve_id))
    {
        handle_errors();
        goto cleanup;
    }

    // Create the parameters from paramater context
    if (!EVP_PKEY_paramgen(params_ctx, &params))
    {
        handle_errors();
        goto cleanup;
    }

    // Create the context for the key generation
    if (NULL == (ecdh_ctx = EVP_PKEY_CTX_new(params, NULL)))
    {
        handle_errors();
        goto cleanup;
    }

    // Generate the key pair
    if (1 != EVP_PKEY_keygen_init(ecdh_ctx))
    {
        handle_errors();
        goto cleanup;
    }
    if (1 != EVP_PKEY_keygen(ecdh_ctx, key_pair))
    {
        handle_errors();
    }

cleanup:
    EVP_PKEY_CTX_free(ecdh_ctx);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(params_ctx);
}

void dh_generate_key_pair(EVP_PKEY **key_pair, enum DHKeySize key_size)
{
    // EVP_PKEY_assign() should transfer the content ownership of this variable
    // to EVP_PKEY *, so no need to free later on
    DH *dh;
    switch (key_size)
    {
    case DH_KEY_SIZE_1024_160:
        dh = DH_get_1024_160();
        break;
    case DH_KEY_SIZE_2048_224:
        dh = DH_get_2048_224();
        break;
    case DH_KEY_SIZE_2048_256:
        dh = DH_get_2048_256();
        break;
    default:
        printf("Invalid key size");
        goto cleanup;
    }

    EVP_PKEY *params = NULL;
    EVP_PKEY_CTX *dh_ctx;

    // Use built-in parameters
    if (NULL == (params = EVP_PKEY_new()))
    {
        handle_errors();
        goto cleanup;
    }
    if (1 != EVP_PKEY_assign(params, EVP_PKEY_DHX, dh))
    {
        handle_errors();
        goto cleanup;
    }

    // Create context for the key generation
    if (!(dh_ctx = EVP_PKEY_CTX_new(params, NULL)))
    {
        handle_errors();
        goto cleanup;
    }

    // Generate the key pair
    if (1 != EVP_PKEY_keygen_init(dh_ctx))
    {
        handle_errors();
        goto cleanup;
    }
    if (1 != EVP_PKEY_keygen(dh_ctx, key_pair))
    {
        handle_errors();
        goto cleanup;
    }

cleanup:
    EVP_PKEY_CTX_free(dh_ctx);
    EVP_PKEY_free(params);
}

void dh_generate_key_pair_from_peer_publib_key(EVP_PKEY **key_pair,
                                               EVP_PKEY *peer_pub_key)
{
    // --- Variables ---
    EVP_PKEY_CTX *dh_ctx = NULL;

    // --- Create Diffie Hellman context from peer key ---
    if ((dh_ctx = EVP_PKEY_CTX_new(peer_pub_key, NULL)) == NULL)
    {
        handle_errors();
        goto cleanup;
    }
    if (EVP_PKEY_keygen_init(dh_ctx) <= 0)
    {
        handle_errors();
        goto cleanup;
    }

    // --- Create key pair from Diffie Hellman context ---
    *key_pair = EVP_PKEY_new();
    if (EVP_PKEY_keygen(dh_ctx, key_pair) <= 0)
    {
        handle_errors();
    }

    // --- Cleanup ---
cleanup:
    EVP_PKEY_CTX_free(dh_ctx);
}

void dh_parse_public_key(EVP_PKEY **pub_key, unsigned char *pub_key_buf,
                         size_t pub_key_buf_len)
{
    // d2i_PUBKEY would alter the buffer pointer passed to it (second argument)
    // base on the its value, and we would lose the referece to the original
    // buffer, hence, we should pass in a copy of the demand argument before
    // passing to leave the original intact in order to free it later
    unsigned char *pub_key_buf_tmp = pub_key_buf;
    // Convert to EVP_PKEY representation
    if (d2i_PUBKEY(pub_key, (const unsigned char **)&pub_key_buf_tmp,
                   pub_key_buf_len) == NULL)
    {
        handle_errors();
    }
}

void dh_generate_shared_secret(EVP_PKEY *key_pair, EVP_PKEY *peer_pub_key,
                               unsigned char **shared_secret,
                               size_t *shared_secret_len)
{
    // --- Variables ---
    EVP_PKEY_CTX *shared_secret_ctx = NULL;

    // --- Creates shared secret ---
    shared_secret_ctx = EVP_PKEY_CTX_new(key_pair, NULL);
    if (EVP_PKEY_derive_init(shared_secret_ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(shared_secret_ctx, peer_pub_key) <= 0)
    {
        handle_errors();
        goto cleanup;
    }
    // Determine the length of the shared secret
    if (EVP_PKEY_derive(shared_secret_ctx, NULL, shared_secret_len) <= 0)
    {
        handle_errors();
        goto cleanup;
    }
    // Create the secret buffer
    *shared_secret = OPENSSL_malloc(*shared_secret_len);
    // DERIVE THE SHARED SECRET
    if ((EVP_PKEY_derive(shared_secret_ctx, *shared_secret,
                         shared_secret_len)) <= 0)
    {
        handle_errors();
    }

    // --- Cleanup ---
cleanup:
    EVP_PKEY_CTX_free(shared_secret_ctx);
}

void extract_public_key(EVP_PKEY *key_pair, unsigned char **pub_key_buf,
                        size_t *pub_key_buf_len)
{
    BIO *bio = BIO_new(BIO_s_mem());
    i2d_PUBKEY_bio(bio, key_pair);
    // Get der-encoded public key
    BUF_MEM *bio_mem;
    BIO_get_mem_ptr(bio, &bio_mem);
    BIO_set_close(bio, BIO_NOCLOSE); // tell BIO_free() to leave BUF_MEM alone
    BIO_free(bio);

    // Allocate the public key
    *pub_key_buf_len = bio_mem->length;
    *pub_key_buf = malloc(bio_mem->length);
    memcpy(*pub_key_buf, (unsigned char *)bio_mem->data, bio_mem->length);

    BUF_MEM_free(bio_mem);
}
