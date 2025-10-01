#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <unistd.h>

// ---- Inlined helpers to remove dependency on ../RequiredFunctionsHW3.c ----
#define LENGTH_OF_EACH_MESSAGE 64
#define NUMBER_OF_MESSAGES 4

static unsigned char* Read_File(char fileName[], int *fileLen) {
    FILE *pFile = fopen(fileName, "r");
    if (pFile == NULL) {
        printf("Error opening file.\n");
        exit(0);
    }
    fseek(pFile, 0L, SEEK_END);
    int temp_size = ftell(pFile) + 1;
    fseek(pFile, 0L, SEEK_SET);
    unsigned char *output = (unsigned char*) malloc(temp_size);
    fgets((char*)output, temp_size, pFile);
    fclose(pFile);
    *fileLen = temp_size - 1;
    return output;
}

static void write_plaintexts(const char *file_name, unsigned char (*lines)[LENGTH_OF_EACH_MESSAGE], int num_lines) {
    FILE *pFile = fopen(file_name, "w");
    if (!pFile) {
        fprintf(stderr, "Error opening file '%s' for writing.\n", file_name);
        exit(1);
    }
    for (int i = 0; i < num_lines; i++) {
        // Write up to 64 bytes; rely on data being ASCII without embedded NULs
        fwrite(lines[i], 1, LENGTH_OF_EACH_MESSAGE, pFile);
        if (i < num_lines - 1) fputc('\n', pFile);
    }
    fclose(pFile);
}

static void AES256CTR_Decrypt(const unsigned char *key, const unsigned char *input, int input_len, unsigned char *output) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    unsigned char iv[16] = "1234567890uvwxyz";
    EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, output, &len, input, input_len);
    EVP_DecryptFinal_ex(ctx, output + len, &len);
    EVP_CIPHER_CTX_free(ctx);
}

static int hex_char_to_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static int parse_hex_string_into_bytes(const char *hex, int hex_len, unsigned char *out_bytes, int out_len) {
    if (hex_len != out_len * 2) return 0;
    for (int i = 0; i < out_len; i++) {
        int hi = hex_char_to_value(hex[2 * i]);
        int lo = hex_char_to_value(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        out_bytes[i] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <SharedSeed.txt> <Ciphertexts.txt>\n", argv[0]);
        return 1;
    }

    // Read seed
    int seed_len = 0;
    unsigned char *seed = Read_File(argv[1], &seed_len);
    if (!seed) {
        fprintf(stderr, "Failed to read seed file.\n");
        return 1;
    }
    if (seed_len > 0 && seed[seed_len - 1] == '\n') {
        seed[seed_len - 1] = '\0';
        seed_len -= 1;
    }

    // Read ciphertext hex lines
    FILE *fp = fopen(argv[2], "r");
    if (!fp) {
        fprintf(stderr, "Error opening file '%s'\n", argv[2]);
        return 1;
    }

    unsigned char plaintexts[NUMBER_OF_MESSAGES][LENGTH_OF_EACH_MESSAGE];
    memset(plaintexts, 0, sizeof(plaintexts));

    unsigned char current_key[SHA256_DIGEST_LENGTH];
    SHA256(seed, (size_t)seed_len, current_key);

    char *line_buf = NULL;
    size_t line_buf_size = 0;
    ssize_t line_size;

    for (int i = 0; i < NUMBER_OF_MESSAGES; i++) {
        line_size = getline(&line_buf, &line_buf_size, fp);
        if (line_size < 0) {
            fprintf(stderr, "Unexpected EOF while reading ciphertext line %d\n", i + 1);
            fclose(fp);
            free(line_buf);
            free(seed);
            return 1;
        }
        if (line_size > 0 && line_buf[line_size - 1] == '\n') {
            line_buf[--line_size] = '\0';
        }

        // Expect 128 hex chars -> 64 bytes
        if ((int)line_size != LENGTH_OF_EACH_MESSAGE * 2) {
            // Allow shorter if there are no leading zeros, but our vectors are fixed length so enforce strictly
            // Fallback: zero-pad or error. We choose error to match test vectors precisely.
            fprintf(stderr, "Ciphertext line %d has unexpected length %zd (expected %d)\n", i + 1, line_size, LENGTH_OF_EACH_MESSAGE * 2);
            fclose(fp);
            free(line_buf);
            free(seed);
            return 1;
        }

        unsigned char ct_bytes[LENGTH_OF_EACH_MESSAGE];
        memset(ct_bytes, 0, sizeof(ct_bytes));
        if (!parse_hex_string_into_bytes(line_buf, (int)line_size, ct_bytes, LENGTH_OF_EACH_MESSAGE)) {
            fprintf(stderr, "Invalid hex in ciphertext line %d\n", i + 1);
            fclose(fp);
            free(line_buf);
            free(seed);
            return 1;
        }

        // Decrypt using current key
        AES256CTR_Decrypt(current_key, ct_bytes, LENGTH_OF_EACH_MESSAGE, plaintexts[i]);

        // Next key = SHA256(current_key)
        unsigned char next_key[SHA256_DIGEST_LENGTH];
        SHA256(current_key, SHA256_DIGEST_LENGTH, next_key);
        memcpy(current_key, next_key, SHA256_DIGEST_LENGTH);
    }

    fclose(fp);
    free(line_buf);

    // Write plaintexts (each is 64 chars)
    write_plaintexts("Plaintexts.txt", plaintexts, NUMBER_OF_MESSAGES);

    free(seed);
    return 0;
}


