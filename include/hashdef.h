#ifndef HASHDEF_H
#define HASHDEF_H

/*
 * Use this macro to define SHA hashing implementation for a given digest size
 * (e.g. DEFINE_HASH_OFSIZE(256) for 256-bit SHA hash).
 */

#define DEFINE_SHA_OFSIZE(digest_size)                                         \
  typedef struct {                                                             \
    unsigned char data[(digest_size) / 8];                                       \
  } hash_buffer_##digest_size##_t;                                             \
                                                                               \
  size_t compute_sha##digest_size##_hash(hash_buffer_##digest_size##_t* buf,   \
                                         unsigned char* msg, size_t msg_len) { \
    const EVP_MD* digest = EVP_sha##digest_size();                             \
    EVP_MD_CTX* digest_ctx = EVP_MD_CTX_new();                                 \
    unsigned int hash_len;                                                     \
    EVP_DigestInit(digest_ctx, digest);                                        \
    EVP_DigestUpdate(digest_ctx, msg, msg_len);                                \
    EVP_DigestFinal_ex(digest_ctx, &buf->data[0], &hash_len);                  \
    EVP_MD_CTX_free(digest_ctx);                                               \
    return hash_len;                                                           \
  }

#endif
