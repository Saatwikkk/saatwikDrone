#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "uECC.h"

// Function to generate public/private key pair
void Generate_KeyPair(uint8_t *public_key, uint8_t *private_key, uECC_Curve curve) {
    if (!uECC_make_key(public_key, private_key, curve)) {
        printf("Error generating key pair\n");
    }
}

// Function to encrypt data (simple XOR with shared secret for demonstration)
void Encrypt_Data(uint8_t *shared_secret, uint8_t *data, uint16_t length, uint8_t *encrypted_data) {
    for (int i = 0; i < length; i++) {
        encrypted_data[i] = data[i] ^ shared_secret[i % 32]; // XOR encryption
    }
}

// Function to decrypt data (simple XOR with shared secret for demonstration)
void Decrypt_Data(uint8_t *shared_secret, uint8_t *encrypted_data, uint16_t length, uint8_t *decrypted_data) {
    for (int i = 0; i < length; i++) {
        decrypted_data[i] = encrypted_data[i] ^ shared_secret[i % 32]; // XOR decryption
    }
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

    // Generate shared secret using the public key and private key
    if (!uECC_shared_secret(public_key, private_key, shared_secret, curve)) {
        printf("Error generating shared secret\n");
        return 1;
    }

    Encrypt_Data(shared_secret, (uint8_t *)input, input_length, encrypted_data);

    // Print encrypted data
    printf("Encrypted Data: ");
    for (int i = 0; i < input_length; i++) {
        printf("%02X", encrypted_data[i]);
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
        // Decrypt data
        Decrypt_Data(shared_secret, encrypted_data, input_length, decrypted_data);

        // Print decrypted data
        printf("Decrypted Data: ");
        for (int i = 0; i < input_length; i++) {
            printf("%c", decrypted_data[i]);
        }
        printf("\n");
    } else {
        printf("Incorrect private key. Cannot decrypt data.\n");
    }

    return 0;
}