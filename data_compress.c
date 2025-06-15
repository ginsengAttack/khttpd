#include "data_compress.h"

bool data_compress(const char *file,
                   unsigned int file_len,
                   char *comp_file,
                   unsigned int *comp_len)
{
    struct crypto_comp *comp;
    comp = crypto_alloc_comp("deflate", 0, 0);
    if (IS_ERR(comp)) {
        return false;
    }

    int ret = crypto_comp_compress(comp, file, file_len, comp_file, comp_len);

    if (ret) {
        crypto_free_comp(comp);
        return false;
    }

    crypto_free_comp(comp);
    return true;
}
