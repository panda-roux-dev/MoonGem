#include "cert.h"

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <stdlib.h>

#include "hashdef.h"
#include "log.h"

#define MODULUS_BUFFER_SIZE 512  // (4096 / 8)

DEFINE_SHA_OFSIZE(256)

void destroy_client_cert(client_cert_t* cert) {
  if (cert != NULL) {
    if (cert->fingerprint != NULL) {
      free(cert->fingerprint);
    }

    free(cert);
  }
}

static size_t get_modulus_from_x509(X509* certificate, unsigned char* buffer) {
  EVP_PKEY* key = X509_get_pubkey(certificate);

  struct rsa_st* rsa = EVP_PKEY_get1_RSA(key);
  if (rsa == NULL) {
    EVP_PKEY_free(key);
    return 0;
  }

  const BIGNUM* modulus = RSA_get0_n(rsa);

  // store key contents in a buffer
  size_t length;
  length = BN_num_bytes(modulus);
  BN_bn2bin(modulus, buffer);

  RSA_free(rsa);
  EVP_PKEY_free(key);

  return length;
}

unsigned int get_x509_expiration(X509* certificate) {
  ASN1_TIME* notafter = X509_get_notAfter(certificate);
  ASN1_TIME* epoch = ASN1_TIME_new();
  ASN1_TIME_set_string(epoch, "700101000000Z");

  int days;
  int seconds;
  ASN1_TIME_diff(&days, &seconds, epoch, notafter);

  ASN1_TIME_free(epoch);

  return (days * 24 * 60 * 60) + seconds;
}

int handle_client_certificate(int preverify_ok, X509_STORE_CTX* ctx) {
  SSL* ssl =
      X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());

  X509* x509 = X509_STORE_CTX_get0_cert(ctx);
  client_cert_t* cert = (client_cert_t*)SSL_get_ex_data(ssl, CLIENT_CERT_INDEX);

  if (cert != NULL && !cert->initialized) {
    // set this flag so that we don't perform this logic multiple times (leading
    // to memory leaks when re-allocating the fingerprint needlessly)
    //
    // i tried to work around this with SSL_VERIFY_CLIENT_ONCE and depth=0, but
    // apparently OpenSSL has other plans and it isn't telling me what they are;
    // so we have to do this
    cert->initialized = true;

    unsigned char modulus[MODULUS_BUFFER_SIZE];
    size_t mod_len = get_modulus_from_x509(x509, &modulus[0]);
    if (mod_len == 0) {
      // couldn't get the certificate modulus; nothing left to do
      return 0;
    }

    hash_buffer_256_t hash;
    size_t hash_len = compute_sha256_hash(&hash, modulus, mod_len);

    // allocate space for each hash byte to be illustrated as 2 characters, plus
    // a null terminator
    const size_t fingerprint_len = hash_len * 2;
    cert->fingerprint = malloc((fingerprint_len + 1) * sizeof(char));
    if (cert->fingerprint == NULL) {
      LOG_ERROR("Failed to allocate space for certificate fingerprint");
      return 0;
    }

    char* hex = cert->fingerprint;
    for (int i = 0; i < hash_len; ++i) {
      hex += sprintf(hex, "%02x", hash.data[i]);
    }

    LOG_DEBUG("Client certificate fingerprint: %s", cert->fingerprint);

    cert->fingerprint[fingerprint_len] = '\0';
    cert->not_after = get_x509_expiration(x509);
  }

  return 1;
}
