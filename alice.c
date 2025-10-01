#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

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

static void Read_Multiple_Lines_from_File(char fileName[], unsigned char message[][LENGTH_OF_EACH_MESSAGE], int num) {
    char *line_buf = NULL;
    size_t line_buf_size = 0;
    ssize_t line_size;
    FILE *fp = fopen(fileName, "r");
    if (!fp) {
        fprintf(stderr, "Error opening file '%s'\n", fileName);
        exit(1);
    }
    line_size = getline(&line_buf, &line_buf_size, fp);
    for (int j = 0; line_size >= 0 && j < num; j++) {
        if (line_size > 0 && line_buf[line_size - 1] == '\n') line_buf[--line_size] = '\0';
        memset(message[j], 0, LENGTH_OF_EACH_MESSAGE);
        int copy_len = (line_size < LENGTH_OF_EACH_MESSAGE) ? (int)line_size : LENGTH_OF_EACH_MESSAGE;
        memcpy(message[j], line_buf, copy_len);
        line_size = getline(&line_buf, &line_buf_size, fp);
    }
    free(line_buf);
    fclose(fp);
}

static void Convert_to_Hex(char output[], unsigned char input[], int inputlength) {
    const char hex_digits[] = "0123456789abcdef";
    for (int i = 0; i < inputlength; i++) {
        output[2 * i] = hex_digits[(input[i] >> 4) & 0x0F];
        output[2 * i + 1] = hex_digits[input[i] & 0x0F];
    }
}

static void AES256CTR_Encrypt(const unsigned char *key, const unsigned char *input, int input_len, unsigned char *output) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    unsigned char iv[16] = "1234567890uvwxyz";
    EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, output, &len, input, input_len);
    EVP_EncryptFinal_ex(ctx, output + len, &len);
    EVP_CIPHER_CTX_free(ctx);
}

static void write_lines_fixed_len(const char *file_name, char (*lines)[256], int line_len, int num_lines) {
    FILE *fp = fopen(file_name, "w");
    if (!fp) {
        fprintf(stderr, "Error opening file '%s' for writing.\n", file_name);
        exit(1);
    }
    for (int i = 0; i < num_lines; i++) {
        // Ensure null-terminated
        lines[i][line_len] = '\0';
        fputs(lines[i], fp);
        if (i < num_lines - 1) fputc('\n', fp);
    }
    fclose(fp);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <SharedSeed.txt> <Messages.txt>\n", argv[0]);
        return 1;
    }

    // Read seed
    int seed_len = 0;
    unsigned char *seed = Read_File(argv[1], &seed_len);
    if (!seed) {
        fprintf(stderr, "Failed to read seed file.\n");
        return 1;
    }
    // Trim possible trailing newline
    if (seed_len > 0 && seed[seed_len - 1] == '\n') {
        seed[seed_len - 1] = '\0';
        seed_len -= 1;
    }

    // Read messages (fixed 64 bytes each, NUMBER_OF_MESSAGES lines)
    unsigned char messages[NUMBER_OF_MESSAGES][LENGTH_OF_EACH_MESSAGE];
    memset(messages, 0, sizeof(messages));
    Read_Multiple_Lines_from_File(argv[2], messages, NUMBER_OF_MESSAGES);

    // Derive first key = SHA256(seed)
    unsigned char current_key[SHA256_DIGEST_LENGTH];
    SHA256(seed, (size_t)seed_len, current_key);

    // Buffers for outputs
    unsigned char ciphertexts[NUMBER_OF_MESSAGES][LENGTH_OF_EACH_MESSAGE];
    memset(ciphertexts, 0, sizeof(ciphertexts));

    // Hex string buffers (ensure room for null terminator)
    char keys_hex[NUMBER_OF_MESSAGES][256];
    char cts_hex[NUMBER_OF_MESSAGES][256];
    memset(keys_hex, 0, sizeof(keys_hex));
    memset(cts_hex, 0, sizeof(cts_hex));

    for (int i = 0; i < NUMBER_OF_MESSAGES; i++) {
        // Encrypt one 64-byte block with AES-256-CTR
        AES256CTR_Encrypt(current_key, messages[i], LENGTH_OF_EACH_MESSAGE, ciphertexts[i]);

        // Convert key (32 bytes) to 64-char hex
        Convert_to_Hex(keys_hex[i], current_key, SHA256_DIGEST_LENGTH);
        keys_hex[i][SHA256_DIGEST_LENGTH * 2] = '\0';

        // Convert ciphertext (64 bytes) to 128-char hex
        Convert_to_Hex(cts_hex[i], ciphertexts[i], LENGTH_OF_EACH_MESSAGE);
        cts_hex[i][LENGTH_OF_EACH_MESSAGE * 2] = '\0';

        // Compute next key = SHA256(current_key)
        unsigned char next_key[SHA256_DIGEST_LENGTH];
        SHA256(current_key, SHA256_DIGEST_LENGTH, next_key);
        memcpy(current_key, next_key, SHA256_DIGEST_LENGTH);
    }

    // Write Keys.txt (each line 64 chars) and Ciphertexts.txt (each line 128 chars)
    write_lines_fixed_len("Keys.txt", keys_hex, SHA256_DIGEST_LENGTH * 2, NUMBER_OF_MESSAGES);
    write_lines_fixed_len("Ciphertexts.txt", cts_hex, LENGTH_OF_EACH_MESSAGE * 2, NUMBER_OF_MESSAGES);

    free(seed);
    return 0;
}


