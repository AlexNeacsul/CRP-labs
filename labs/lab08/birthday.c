#include <openssl/evp.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* We want a collision in the first 4 bytes = 2^16 attempts */
#define N_BITS 16
#define BUFLEN 10
#define N_MSGS (1 << N_BITS)

typedef struct
{
    unsigned char message[BUFLEN];
    uint32_t hash_prefix;
} entry_t;

int raw2int4(unsigned char *digest)
{
    int i;
    int sum = 0;

    for (i = 0; i < 4; i++)
    {
        sum = (sum << 8) | digest[i];
    }

    return sum;
}

void hexdump(unsigned char *string, int length)
{
    int i;
    for (i = 0; i < length; i++)
    {
        printf("%02x", string[i]);
    }
}

int compare(const void *a, const void *b)
{
    uint32_t ha = ((entry_t *)a)->hash_prefix;
    uint32_t hb = ((entry_t *)b)->hash_prefix;
    if (ha < hb)
        return -1;
    if (ha > hb)
        return 1;
    return 0;
}

int main(int argc, char *argv[])
{
    EVP_MD_CTX *mdctx;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    entry_t *entries;
    int i, j;
    int found = 0;

    srand(time(NULL));
    entries = malloc(sizeof(entry_t) * N_MSGS);
    if (!entries)
    {
        perror("malloc");
        exit(1);
    }

    /* Step 1: Generate random messages */
    for (i = 0; i < N_MSGS; i++)
    {
        for (j = 0; j < BUFLEN; j++)
        {
            entries[i].message[j] = rand() & 0xFF;
        }
    }

    /* Step 2: Hash all messages */
    for (i = 0; i < N_MSGS; i++)
    {
        mdctx = EVP_MD_CTX_new();
        if (!mdctx)
        {
            perror("EVP_MD_CTX_new");
            exit(1);
        }
        if (EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL) != 1)
        {
            perror("EVP_DigestInit_ex");
            exit(1);
        }
        if (EVP_DigestUpdate(mdctx, entries[i].message, BUFLEN) != 1)
        {
            perror("EVP_DigestUpdate");
            exit(1);
        }
        if (EVP_DigestFinal_ex(mdctx, md, &md_len) != 1)
        {
            perror("EVP_DigestFinal_ex");
            exit(1);
        }
        entries[i].hash_prefix = raw2int4(md); // Store the first 4 bytes as uint32_t
        EVP_MD_CTX_free(mdctx);
    }

    /* Step 3: Sort entries based on hash_prefix */
    qsort(entries, N_MSGS, sizeof(entry_t), compare);

    /* Step 4: Search for a collision */
    for (i = 0; i < N_MSGS - 1; i++)
    {
        if (entries[i].hash_prefix == entries[i + 1].hash_prefix)
        {
            printf("Collision found!\n");
            printf("Message 1: ");
            hexdump(entries[i].message, BUFLEN);
            printf("\nMessage 2: ");
            hexdump(entries[i + 1].message, BUFLEN);
            printf("\nHash prefix: %08x\n", entries[i].hash_prefix);
            found = 1;
            break;
        }
    }

    if (!found)
    {
        printf("No collision found. Try again.\n");
    }

    free(entries);
    return 0;
}