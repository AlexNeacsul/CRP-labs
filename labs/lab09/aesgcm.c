#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

void hexdump(unsigned char * string, int length) {
    int i;
    for (i = 0; i < length; i++) {
        printf("%02x", string[i]);
    }
}


int aes_gcm_encrypt(unsigned char * ptext,
                    int plen,
                    unsigned char * key,
                    unsigned char * iv,
                    unsigned char ** ctext,
                    int * clen) {

    EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP_CIPHER_CTX\n");
        return -1;
    }

    // Initialize context for AES-256-GCM encryption
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        fprintf(stderr, "EVP_EncryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Set IV length (12 bytes = 96 bits recommended for GCM)
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)) {
        fprintf(stderr, "EVP_CIPHER_CTX_ctrl failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Initialize key and IV
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
        fprintf(stderr, "EVP_EncryptInit_ex key/iv failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Allocate memory for ciphertext + 16 bytes tag
    *ctext = (unsigned char *)malloc(plen + 16);
    if (!*ctext) {
        fprintf(stderr, "Failed to allocate memory for ciphertext\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int outlen;
    // Encrypt plaintext
    if (1 != EVP_EncryptUpdate(ctx, *ctext, &outlen, ptext, plen)) {
        fprintf(stderr, "EVP_EncryptUpdate failed\n");
        free(*ctext);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *clen = outlen;

    // Finalize encryption
    if (1 != EVP_EncryptFinal_ex(ctx, *ctext + outlen, &outlen)) {
        fprintf(stderr, "EVP_EncryptFinal_ex failed\n");
        free(*ctext);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *clen += outlen;

    // Get tag (16 bytes)
    unsigned char tag[16];
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
        fprintf(stderr, "EVP_CIPHER_CTX_ctrl GET_TAG failed\n");
        free(*ctext);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Append tag to the end of ciphertext
    memcpy(*ctext + *clen, tag, 16);
    *clen += 16;

    printf("Tag (hex) = ");
    hexdump(tag, 16);
    printf("\n");

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int aes_gcm_decrypt(unsigned char * ctext,
                    int clen,
                    unsigned char * key,
                    unsigned char * iv,
                    unsigned char ** ptext,
                    int * plen) {

    EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP_CIPHER_CTX\n");
        return -1;
    }

    // Initialize context for AES-256-GCM decryption
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        fprintf(stderr, "EVP_DecryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Set IV length
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)) {
        fprintf(stderr, "EVP_CIPHER_CTX_ctrl failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Initialize key and IV
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
        fprintf(stderr, "EVP_DecryptInit_ex key/iv failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Extract tag from the end of ciphertext
    unsigned char tag[16];
    memcpy(tag, ctext + clen - 16, 16);

    // Ciphertext length without tag
    int ctext_len = clen - 16;

    // Allocate memory for plaintext
    *ptext = (unsigned char *)malloc(ctext_len);
    if (!*ptext) {
        fprintf(stderr, "Failed to allocate memory for plaintext\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int outlen;
    // Decrypt ciphertext (excluding tag)
    if (1 != EVP_DecryptUpdate(ctx, *ptext, &outlen, ctext, ctext_len)) {
        fprintf(stderr, "EVP_DecryptUpdate failed\n");
        free(*ptext);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *plen = outlen;

    // Set expected tag value before finalizing
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) {
        fprintf(stderr, "EVP_CIPHER_CTX_ctrl SET_TAG failed\n");
        free(*ptext);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Finalize decryption (verifies tag)
    int ret = EVP_DecryptFinal_ex(ctx, *ptext + outlen, &outlen);
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        // Success
        *plen += outlen;
        return 0;
    } else {
        // Verification failed
        fprintf(stderr, "Decryption failed: tag verification failure\n");
        free(*ptext);
        *ptext = NULL;
        *plen = 0;
        return -1;
    }
}
int main(int argc, char * argv[]) {
    ERR_load_crypto_strings();

    unsigned char key[] = "0123456789abcdef0123456789abcdef"; /* 256-bit key */
    unsigned char iv[] = "0123456789ab";                      /* 96-bit IV   */

    unsigned char * ptext = (unsigned char *)"Hello, SSLWorld!\n";
    int plen = strlen((const char *)ptext);

    unsigned char * ctext;
    int clen;

    printf("Plaintext = %s\n", ptext);
    printf("Plaintext  (hex) = "); hexdump(ptext, plen); printf("\n");

    aes_gcm_encrypt(ptext, plen, key, iv, &ctext, &clen);
    printf("Ciphertext (hex) = "); hexdump(ctext, clen - 16); printf("\n");

    unsigned char * ptext2;
    int plen2;
    aes_gcm_decrypt(ctext, clen, key, iv, &ptext2, &plen2);
    printf("Done decrypting!\n");

    ptext2[plen2] = '\0';
    printf("Plaintext = %s\n", ptext2);

    if (memcmp(ptext, ptext2, strlen((const char *)ptext)) == 0) {
        printf("Ok!\n");
    } else {
        printf("Not ok :(\n");
    }

    return 0;
}
