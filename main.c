#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#ifndef READ_PUB_KEY
#define READ_PUB_KEY 2
#endif

void handle_errors()
{
    int e = ERR_get_error();
    printf("%s\n", ERR_error_string(e, NULL));
}

void print_hex_with_delim(const unsigned char *buf, size_t len, char delim[])
{
    size_t i;
    for (i = 0; i < len; i++)
    {
        printf("%02X", *(buf + i));
        if (i < len - 1)
            printf("%s", delim);
    }
    putchar('\n');
}

void print_hex(const unsigned char *buf, size_t len)
{
    print_hex_with_delim(buf, len, "");
}

void str_to_hex(const char *buf, size_t *len, unsigned char **hex)
{

    if ((*len & 1) != 0)
    {
        printf("str_to_hex: len should be even\n");
        return;
    }

    *hex = OPENSSL_malloc(*len / 2);
    if (*hex == NULL)
    {
        handle_errors();
        return;
    }

    size_t i;
    unsigned int uchr;
    for (i = 0; i < *len; i += 2)
    {
        sscanf(buf + i, "%02X", &uchr);
        (*hex)[i / 2] = uchr;
    }

    *len = *len / 2;
}

/*
 * Second phase is the same for both DH and ECDH
 */
#if READ_PUB_KEY == 2
void dh_second_phase(unsigned char *_alice_pub_key_buf, size_t _alice_pub_key_len)
#else
void dh_second_phase()
#endif
{
    // --- Variables ---
    unsigned char *alice_pub_key_buf = NULL;
    EVP_PKEY *alice_pub_key = NULL;
    EVP_PKEY *bob_key_pair = NULL;
    EVP_PKEY_CTX *bob_dh_ctx = NULL;
    EVP_PKEY_CTX *shared_secret_ctx = NULL;
    unsigned char *secret = NULL;

    // --- Get Alice's public key ---
#if READ_PUB_KEY == 0
    char alice_pub_key_arr[] = "308202283082011B06092A864886F70D0103013082010C0282010100FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF0201020202040003820105000282010023D97889A985F7909F98F3605A148BABC1C39A07380ADBA5AF01EDBD0FCA7CA3AF36A7A95313C2C8E409CD62A64320F9315589108F2061D01270C663A3CD3113D630E9DD106E65471958081D74B46ACF81983E63D5C85CBBD81C50F94602B7B91F4DC7B58AF6355C3F8594AE3F050AB5F8FE576131C13997E07AAD8756A858343486AAD89B46216FE7121B1E71865634CACE0E65DA24536AD84809BC4A4E6C1C3A82B38BA7F978FBDA4CBA511882B80D8F11C9D12C93A6EDE854A90CD923742ABA4EF9768D1E5CEFF7D14554450FC1005D9CCCB916AAA0EDD8B1154C9534EF85B146CD79F3016140C890C79F98C6F4F215DFD44CC555A8C5F903C364015F85B0";
#elif READ_PUB_KEY == 1
    printf("Alice's public key: ");
    char alice_pub_key_arr[4069];
    scanf("%s", alice_pub_key_arr);
#endif
    // Prepare Alice's raw public key and its length
#if READ_PUB_KEY == 2
    size_t alice_pub_key_len = _alice_pub_key_len;
    alice_pub_key_buf = _alice_pub_key_buf;
#else
    size_t alice_pub_key_len = strlen(alice_pub_key_arr);
    str_to_hex(alice_pub_key_arr, &alice_pub_key_len, &alice_pub_key_buf);
#endif
    if (alice_pub_key_buf == NULL)
    {
        goto cleanup;
    }
    // Print Alice's public key
#if READ_PUB_KEY == 0
    printf("Alice's public key: ");
    print_hex(alice_pub_key_buf, alice_pub_key_len);
#endif
    // d2i_PUBKEY would alter the buffer pointer passed to it (second argument)
    // base on the its value, and we would lose the referece to the original
    // buffer, hence, we should pass in a copy of the demand argument before
    // passing to leave the original intact in order to free it later
    unsigned char *alice_pub_key_buf_tmp = alice_pub_key_buf;
    // Convert to EVP_PKEY representation
    if (d2i_PUBKEY(&alice_pub_key, (const unsigned char **)&alice_pub_key_buf_tmp,
                   alice_pub_key_len) == NULL)
    {
        handle_errors();
        goto cleanup;
    }

    // --- Create Bob's Diffie Hellman context ---
    bob_key_pair = EVP_PKEY_new();
    if ((bob_dh_ctx = EVP_PKEY_CTX_new(alice_pub_key, NULL)) == NULL)
    {
        handle_errors();
        goto cleanup;
    }
    if (EVP_PKEY_keygen_init(bob_dh_ctx) <= 0)
    {
        handle_errors();
        goto cleanup;
    }
    if (EVP_PKEY_keygen(bob_dh_ctx, &bob_key_pair) <= 0)
    {
        handle_errors();
        goto cleanup;
    }

    // --- Send out Bob's public key ---
    BIO *bio = BIO_new(BIO_s_mem());
    i2d_PUBKEY_bio(bio, bob_key_pair);
    // Get Bob's der-encoded public key
    BUF_MEM *bio_mem;
    BIO_get_mem_ptr(bio, &bio_mem);
    BIO_set_close(bio, BIO_NOCLOSE); // tell BIO_free() to leave BUF_MEM alone
    BIO_free(bio);
    // Print Bob's public key
    printf("Bob's public key: ");
    print_hex((unsigned char *)bio_mem->data, bio_mem->length);
    BUF_MEM_free(bio_mem);

    // --- Bob creates shared secret ---
    shared_secret_ctx = EVP_PKEY_CTX_new(bob_key_pair, NULL);
    if (EVP_PKEY_derive_init(shared_secret_ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(shared_secret_ctx, alice_pub_key) <= 0)
    {
        handle_errors();
        goto cleanup;
    }
    // Determine the length of the shared secret
    size_t secret_len;
    if (EVP_PKEY_derive(shared_secret_ctx, NULL, &secret_len) <= 0)
    {
        handle_errors();
        goto cleanup;
    }
    // Create the secret buffer
    secret = OPENSSL_malloc(secret_len);
    // DERIVE THE SHARED SECRET
    if ((EVP_PKEY_derive(shared_secret_ctx, secret, &secret_len)) <= 0)
    {
        handle_errors();
    }
    // Print Bob's generated shared secret
    printf("Shared secret generated by Bob: ");
    print_hex_with_delim(secret, secret_len, ":");

    // --- Cleanup ---
cleanup:
    OPENSSL_free(secret);
    EVP_PKEY_CTX_free(shared_secret_ctx);
    EVP_PKEY_CTX_free(bob_dh_ctx);
    EVP_PKEY_free(bob_key_pair);
    EVP_PKEY_free(alice_pub_key);
#if READ_PUB_KEY != 2
    OPENSSL_free(alice_pub_key_buf);
#endif
}

void ecdh_first_phase()
{
    EVP_PKEY_CTX *params_ctx;
    EVP_PKEY *params = NULL;
    EVP_PKEY_CTX *ecdh_ctx;
    EVP_PKEY *key_pair = NULL;

    /* Create the context for parameter generation */
    if (NULL == (params_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)))
    {
        handle_errors();
        goto cleanup;
    }

    /* Initialise the parameter generation */
    if (1 != EVP_PKEY_paramgen_init(params_ctx))
    {
        handle_errors();
        goto cleanup;
    }

    /* We're going to use the ANSI X9.62 Prime 256v1 curve */
    if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(params_ctx, NID_X9_62_prime256v1))
    {
        handle_errors();
        goto cleanup;
    }

    /* Create the parameter object params */
    if (!EVP_PKEY_paramgen(params_ctx, &params))
    {
        handle_errors();
        goto cleanup;
    }

    /* Create the context for the key generation */
    if (NULL == (ecdh_ctx = EVP_PKEY_CTX_new(params, NULL)))
    {
        handle_errors();
        goto cleanup;
    }

    /* Generate the key */
    if (1 != EVP_PKEY_keygen_init(ecdh_ctx))
    {
        handle_errors();
        goto cleanup;
    }
    if (1 != EVP_PKEY_keygen(ecdh_ctx, &key_pair))
    {
        handle_errors();
        goto cleanup;
    }

    BIO *bio = BIO_new(BIO_s_mem());
    i2d_PUBKEY_bio(bio, key_pair);
    // Get der-encoded public key
    BUF_MEM *bio_mem;
    BIO_get_mem_ptr(bio, &bio_mem);
    BIO_set_close(bio, BIO_NOCLOSE); // tell BIO_free() to leave BUF_MEM alone
    BIO_free(bio);
    //
    printf("Alice's public key: ");
    print_hex((unsigned char *)bio_mem->data, bio_mem->length);

    dh_second_phase((unsigned char *)bio_mem->data, bio_mem->length);

    BUF_MEM_free(bio_mem);

cleanup:
    EVP_PKEY_free(key_pair);
    EVP_PKEY_CTX_free(ecdh_ctx);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(params_ctx);
}

int main()
{
#if READ_PUB_KEY == 2
    ecdh_first_phase();
#else
    dh_second_phase();
#endif

    return EXIT_SUCCESS;
}
