#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <mbedtls/aes.h>
#include <mbedtls/md.h>
#include "uECC.h"

#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define HMAC_KEY_SIZE 32

// Function to generate public/private key pair
void Generate_KeyPair(uint8_t *public_key, uint8_t *private_key, uECC_Curve curve) {
    if (!uECC_make_key(public_key, private_key, curve)) {
        printf("Error generating key pair\n");
    }
}

// Function to derive AES key from shared secret
void Derive_AES_Key(uint8_t *shared_secret, uint8_t *aes_key) {
    memcpy(aes_key, shared_secret, AES_KEY_SIZE); // Use the first 32 bytes as the AES key
}

// Function to encrypt data using AES
void Encrypt_Data_AES(uint8_t *aes_key, uint8_t *data, uint16_t length, uint8_t *encrypted_data, uint8_t *iv) {
    mbedtls_aes_context aes;

    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, aes_key, AES_KEY_SIZE * 8);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, length, iv, data, encrypted_data);
    mbedtls_aes_free(&aes);
}

// Function to decrypt data using AES
void Decrypt_Data_AES(uint8_t *aes_key, uint8_t *encrypted_data, uint16_t length, uint8_t *decrypted_data, uint8_t *iv) {
    mbedtls_aes_context aes;

    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, aes_key, AES_KEY_SIZE * 8);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, length, iv, encrypted_data, decrypted_data);
    mbedtls_aes_free(&aes);
}

// Function to generate HMAC for message authentication
void Generate_HMAC(uint8_t *key, uint8_t *data, uint16_t length, uint8_t *hmac) {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(&ctx, key, HMAC_KEY_SIZE);
    mbedtls_md_hmac_update(&ctx, data, length);
    mbedtls_md_hmac_finish(&ctx, hmac);
    mbedtls_md_free(&ctx);
}

int main() {
    // ECC variables
    uint8_t public_key[64]; // Adjust size according to the curve used
    uint8_t private_key[32]; // Adjust size according to the curve used
    uint8_t shared_secret[32]; // Shared secret size based on secp256r1
    uint8_t input_private_key[32]; // Buffer for user-input private key
    uECC_Curve curve = uECC_secp256r1();

    // Generate key pair
    Generate_KeyPair(public_key, private_key, curve);
    
    // Print keys
    printf("Public Key: ");
    for (int i = 0; i < sizeof(public_key); i++) {
        printf("%02X", public_key[i]);
    }
    printf("\n");

    printf("Private Key: ");
    for (int i = 0; i < sizeof(private_key); i++) {
        printf("%02X", private_key[i]);
    }
    printf("\n");

    // User input
    char input[256];
    printf("Enter data to encrypt: ");
    fgets(input, sizeof(input), stdin);
    size_t input_length = strlen(input);
    if (input[input_length - 1] == '\n') {
        input[input_length - 1] = '\0'; // Remove newline character
        input_length--;
    }

    // Encrypt data
    uint8_t encrypted_data[256];
    uint8_t decrypted_data[256];
    uint8_t iv[AES_BLOCK_SIZE] = {0}; // Simple IV for demonstration; use a random IV in practice

    // Generate shared secret using the public key and private key
    if (!uECC_shared_secret(public_key, private_key, shared_secret, curve)) {
        printf("Error generating shared secret\n");
        return 1;
    }

    // Derive AES key from shared secret
    uint8_t aes_key[AES_KEY_SIZE];
    Derive_AES_Key(shared_secret, aes_key);

    // Encrypt data using AES
    Encrypt_Data_AES(aes_key, (uint8_t *)input, input_length, encrypted_data, iv);

    // Print encrypted data
    printf("Encrypted Data: ");
    for (int i = 0; i < input_length; i++) {
        printf("%02X", encrypted_data[i]);
    }
    printf("\n");

    // Generate HMAC for encrypted data
    uint8_t hmac[32];
    Generate_HMAC(aes_key, encrypted_data, input_length, hmac);

    // Print HMAC
    printf("HMAC: ");
    for (int i = 0; i < sizeof(hmac); i++) {
        printf("%02X", hmac[i]);
    }
    printf("\n");

    // User input for private key
    printf("Enter private key to decrypt: ");
    for (int i = 0; i < sizeof(input_private_key); i++) {
        unsigned int temp;
        scanf("%02X", &temp);
        input_private_key[i] = (uint8_t)temp;
    }

    // Generate shared secret using the public key and user-input private key
    uint8_t input_shared_secret[32];
    if (!uECC_shared_secret(public_key, input_private_key, input_shared_secret, curve)) {
        printf("Error generating shared secret\n");
        return 1;
    }

    // Check if the input private key is correct by comparing shared secrets
    if (memcmp(shared_secret, input_shared_secret, sizeof(shared_secret)) == 0) {
        // Verify HMAC before decrypting
        uint8_t input_hmac[32];
        Generate_HMAC(aes_key, encrypted_data, input_length, input_hmac);
        if (memcmp(hmac, input_hmac, sizeof(hmac)) == 0) {
            // Decrypt data using AES
            Decrypt_Data_AES(aes_key, encrypted_data, input_length, decrypted_data, iv);

            // Print decrypted data
            printf("Decrypted Data: ");
            for (int i = 0; i < input_length; i++) {
                printf("%c", decrypted_data[i]);
            }
            printf("\n");
        } else {
            printf("HMAC verification failed. Cannot decrypt data.\n");
        }
    } else {
        printf("Incorrect private key. Cannot decrypt data.\n");
    }

    return 0;
}
