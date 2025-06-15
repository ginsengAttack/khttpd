#ifndef DATA_COMPRESS_H
#define DATA_COMPRESS_H

#include <linux/crypto.h>

bool data_compress(const char *file,
                   unsigned int file_len,
                   char *comp_file,
                   unsigned int *comp_len);

#endif