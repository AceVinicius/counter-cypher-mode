#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <sys/stat.h>
#include <omp.h>

#include "aes.h"


#define  NUM_OF_ARGS          4
#define  EXEC_NAME_IDX        0
#define  MODE_IDX             1
#define  INPUT_FILE_IDX       2
#define  OUTPUT_FILE_IDX      3
#define  BLOCK_SIZE          16
#define  MIN_TO_OMP       65536


void *     allocate                   (size_t count, size_t size);
FILE *     open_file                  (const char *filename, const char *mode);
uint8_t ** allocate_blocks            (size_t number_of_blocks);
void       deallocate_blocks          (uint8_t **blocks, int number_of_blocks);
off_t      get_file_size              (const char *filename);
int        calculate_number_of_blocks (int size, uint8_t last_block_size);
uint8_t *  generate_nonce_block       (uint8_t *block);
uint8_t *  extract_nonce_from_block   (uint8_t *block);
void       insert_padding_into_block  (uint8_t *block, uint8_t last_block_size);
uint8_t    extract_last_block_size    (uint8_t *block);
uint8_t ** read_file_into_blocks      (uint8_t **blocks, int number_of_blocks, const char *filename, uint8_t last_block_size);
void       write_blocks_into_file     (uint8_t **blocks, int number_of_blocks, const char *filename, uint8_t last_block_size);
void       xor                        (uint8_t *op1, const uint8_t *op2, uint8_t size);
void       mix_nonce_and_counter      (const uint8_t *nonce, long long counter, uint8_t *output);
void       encrypt_block              (const uint8_t *key, const uint8_t *nonce, long long counter, uint8_t *block);
void       ctr_encrypt                (const char *input, const char *output, const uint8_t *key);
void       ctr_decrypt                (const char *input, const char *output, const uint8_t *key);


void *allocate(const size_t count, const size_t size) {
    void *new_memory = calloc(count, size);
    if (new_memory == NULL) {
        perror("allocate");
        exit(EXIT_FAILURE);
    }

    return new_memory;
}


FILE *open_file(const char *const filename, const char *const mode) {
    FILE *new_file = fopen(filename, mode);
    if (new_file == NULL) {
        perror("open_file");
        exit(EXIT_FAILURE);
    }

    return new_file;
}


uint8_t **allocate_blocks(const size_t number_of_blocks) {
    uint8_t **blocks = (uint8_t **) allocate(number_of_blocks, sizeof(uint8_t *));

    #pragma omp parallel for shared(number_of_blocks, blocks) default(none) if(number_of_blocks > MIN_TO_OMP)
    for (int i = 0; i < number_of_blocks; ++i) {
        blocks[ i ] = (uint8_t *) allocate(BLOCK_SIZE, sizeof(uint8_t));
    }

    return blocks;
}


void deallocate_blocks(uint8_t **const blocks, const int number_of_blocks) {
    #pragma omp parallel for shared(number_of_blocks, blocks) default(none) if(number_of_blocks > MIN_TO_OMP)
    for (int i = 0; i < number_of_blocks; ++i) {
        free(blocks[ i ]);
    }

    free(blocks);
}


off_t get_file_size(const char *filename) {
    if (access(filename, F_OK | R_OK) != 0) {
        perror("get_file_size");
        exit(EXIT_FAILURE);
    }

    struct stat st;
    stat(filename, &st);

    return st.st_size;
}


void print_info(const int file_size, const int number_of_blocks, const uint8_t *const nonce, uint8_t **const blocks,
                const uint8_t last_block_size) {
    printf("\n");
    printf("  file_size: %d\n", file_size);
    printf("  number_of_blocks: %d\n\n", number_of_blocks);

    printf("  nonce:   ");
    for (int i = 0; i < BLOCK_SIZE; ++i) {
        if (i % 2 == 0 && i > 0) {
            printf(" ");
        }
        printf("%02X", nonce[ i ]);
    }
    printf("\n");

    printf("  padding: ");
    for (int i = last_block_size; i < BLOCK_SIZE; ++i) {
        if (i % 2 == 0 && i > 0) {
            printf(" ");
        }
        printf("%02X", blocks[ number_of_blocks - 1 ][ i ]);
    }
    printf("\n");
}


int calculate_number_of_blocks(const int size, const uint8_t last_block_size) {
    int number_of_blocks = ceil(size * 1.0 / BLOCK_SIZE);

    if (last_block_size == 0) {
        ++number_of_blocks;
    }

    return number_of_blocks;
}


uint8_t *generate_nonce_block(uint8_t *const block) {
    uint8_t *nonce = (uint8_t *) allocate(BLOCK_SIZE, sizeof(uint8_t));

    arc4random_buf(nonce, BLOCK_SIZE);
    memcpy(block, nonce, BLOCK_SIZE);

    return nonce;
}


uint8_t *extract_nonce_from_block(uint8_t *const block) {
    uint8_t *nonce = (uint8_t *) allocate(BLOCK_SIZE, sizeof(uint8_t));
    memcpy(nonce, block, BLOCK_SIZE);
    return nonce;
}


void insert_padding_into_block(uint8_t *const block, const uint8_t last_block_size) {
    #pragma omp parallel for shared(last_block_size, block) default(none) if(BLOCK_SIZE > MIN_TO_OMP)
    for (int i = last_block_size; i < BLOCK_SIZE; ++i) {
        block[ i ] = 0x00;
    }

    block[ BLOCK_SIZE - 1 ] = (uint8_t) BLOCK_SIZE - last_block_size;
}


uint8_t extract_last_block_size(uint8_t *const block) {
    return BLOCK_SIZE - block[ BLOCK_SIZE - 1 ];
}


uint8_t **read_file_into_blocks(uint8_t **const blocks, const int number_of_blocks, const char *filename,
                                const uint8_t last_block_size) {
    FILE *fd = open_file(filename, "rb");

    for (int i = 0; i < number_of_blocks - 1; ++i) {
        if (fread(blocks[ i ], sizeof(uint8_t), BLOCK_SIZE, fd) != BLOCK_SIZE) {
            fclose(fd);
            deallocate_blocks(blocks, number_of_blocks + 1);
            fprintf(stderr, "read_file_into_blocks: fread: not enough bytes was read\n");
            exit(EXIT_FAILURE);
        }
    }

    if (fread(blocks[ number_of_blocks - 1 ], sizeof(uint8_t), last_block_size, fd) != last_block_size) {
        fclose(fd);
        deallocate_blocks(blocks, number_of_blocks + 1);
        fprintf(stderr, "read_file_into_blocks: fread: not enough bytes was read\n");
        exit(EXIT_FAILURE);
    }

    fclose(fd);

    return blocks;
}


void write_blocks_into_file(uint8_t **const blocks, const int number_of_blocks, const char *filename,
                            const uint8_t last_block_size) {
    FILE *fd = open_file(filename, "wb");

    for (int i = 0; i < number_of_blocks - 1; ++i) {
        if (fwrite(blocks[ i ], sizeof(uint8_t), BLOCK_SIZE, fd) != BLOCK_SIZE) {
            fclose(fd);
            remove(filename);
            deallocate_blocks(blocks, number_of_blocks + 1);
            fprintf(stderr, "write_blocks_into_file: fwrite: not enough bytes was written\n");
            exit(EXIT_FAILURE);
        }
    }

    if (fwrite(blocks[ number_of_blocks - 1 ], sizeof(uint8_t), last_block_size, fd) != last_block_size) {
        fclose(fd);
        remove(filename);
        deallocate_blocks(blocks, number_of_blocks + 1);
        fprintf(stderr, "write_blocks_into_file: fwrite: not enough bytes was written\n");
        exit(EXIT_FAILURE);
    }

    fclose(fd);
}


void xor(uint8_t *const op1, const uint8_t *const op2, const uint8_t size) {
    #pragma omp parallel for shared(op1, op2, size) default(none) if(BLOCK_SIZE > MIN_TO_OMP)
    for (uint8_t i = 0; i < size; ++i) {
        op1[ i ] ^= op2[ i ];
    }
}


void mix_nonce_and_counter(const uint8_t *const nonce, const long long counter, uint8_t *output) {
    memcpy(output, nonce, BLOCK_SIZE);

    // Windows is big endian and linux/unix are little endian, which is a problem to portability
    xor(output, (uint8_t *) &counter, sizeof(long long));
}


void encrypt_block(const uint8_t *const key, const uint8_t *const nonce, const long long counter, uint8_t *const block) {
    uint8_t *input_aes = (uint8_t *) allocate(BLOCK_SIZE, sizeof(uint8_t));
    uint8_t *output_aes = (uint8_t *) allocate(BLOCK_SIZE, sizeof(uint8_t));

    mix_nonce_and_counter(nonce, counter, input_aes);
    AES128_Encrypt(input_aes, key, output_aes);
    xor(block, output_aes, BLOCK_SIZE);

    free(input_aes);
    free(output_aes);
}


void ctr_encrypt(const char *const input, const char *const output, const uint8_t *const key) {
    const int file_size = (int) get_file_size(input);
    const uint8_t last_block_size = file_size % BLOCK_SIZE;
    const int number_of_blocks = calculate_number_of_blocks(file_size, last_block_size);

    uint8_t **blocks = (uint8_t **) allocate_blocks(number_of_blocks + 1);
    read_file_into_blocks(blocks, number_of_blocks, input, last_block_size);
    insert_padding_into_block(blocks[ number_of_blocks - 1 ], last_block_size);

    uint8_t *const nonce = (uint8_t *) generate_nonce_block(blocks[ number_of_blocks ]);

    #pragma omp parallel for shared(number_of_blocks, key, nonce, blocks) default(none) if(number_of_blocks > MIN_TO_OMP)
    for (long long i = 0; i < number_of_blocks; ++i) {
        encrypt_block(key, nonce, i, blocks[ i ]);
    }

    write_blocks_into_file(blocks, number_of_blocks + 1, output, BLOCK_SIZE);

    print_info(file_size, number_of_blocks, nonce, blocks, last_block_size);

    deallocate_blocks(blocks, number_of_blocks + 1);
    free(nonce);
}


void ctr_decrypt(const char *const input, const char *const output, const uint8_t *const key) {
    const int file_size = (int) get_file_size(input);
    const int number_of_blocks = calculate_number_of_blocks(file_size, BLOCK_SIZE) - 1;

    uint8_t **blocks = (uint8_t **) allocate_blocks(number_of_blocks + 1);
    read_file_into_blocks(blocks, number_of_blocks + 1, input, BLOCK_SIZE);

    uint8_t *const nonce = (uint8_t *) extract_nonce_from_block(blocks[ number_of_blocks ]);

    #pragma omp parallel for shared(number_of_blocks, key, nonce, blocks) default(none) if(number_of_blocks > MIN_TO_OMP)
    for (int i = 0; i < number_of_blocks; ++i) {
        encrypt_block(key, nonce, i, blocks[ i ]);
    }

    const uint8_t last_block_size = extract_last_block_size(blocks[ number_of_blocks - 1 ]);
    write_blocks_into_file(blocks, number_of_blocks, output, last_block_size);

    print_info(file_size, number_of_blocks, nonce, blocks, last_block_size);

    deallocate_blocks(blocks, number_of_blocks + 1);
    free(nonce);
}


int main(const int argc, const char ** const argv) {
    if (argc != NUM_OF_ARGS) {
        fprintf(stderr, "usage: %s [enc|dec] [in file] [out file]\n", argv[ EXEC_NAME_IDX ]);
        return EXIT_FAILURE;
    }

    uint8_t *key = (uint8_t *) allocate(BLOCK_SIZE, sizeof(uint8_t));

    printf("\n  mode: CTR\n");
    printf("  padding: ANSI X.923\n");
    printf("\n Enter your key (128 bits): ");
    fgets((char *) key, BLOCK_SIZE, stdin);

    double time_start = omp_get_wtime();

    if (strcmp("enc", argv[ MODE_IDX ]) == 0) {
        ctr_encrypt(argv[ INPUT_FILE_IDX ], argv[ OUTPUT_FILE_IDX ], key);
    } else if (strcmp("dec", argv[ MODE_IDX ]) == 0) {
        ctr_decrypt(argv[ INPUT_FILE_IDX ], argv[ OUTPUT_FILE_IDX ], key);
    } else {
        free(key);
        fprintf(stderr, "usage: %s [enc|dec] [in file] [out file]\n", argv[ EXEC_NAME_IDX ]);
        return EXIT_FAILURE;
    }

    printf("\n  time: %lf seconds\n\n", omp_get_wtime() - time_start);

    free(key);

    return EXIT_SUCCESS;
}
