#include "cert.h"

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <stdlib.h>

#include "hashdef.h"
#include "log.h"

DEFINE_SHA_OFSIZE(256)

static int client_cert_index = 0;

void destroy_client_cert(client_cert_t* cert) {
  if (cert != NULL) {
    if (cert->fingerprint != NULL) {
      free(cert->fingerprint);
    }

    free(cert);
  }
}

int get_client_cert_index(void) { return client_cert_index; }

unsigned char* get_modulus_from_x509(X509* certificate, size_t* len) {
  EVP_PKEY* key = X509_get_pubkey(certificate);

  struct rsa_st* rsa = EVP_PKEY_get1_RSA(key);
  const BIGNUM* modulus = RSA_get0_n(rsa);

  // store key contents in a buffer
  *len = BN_num_bytes(modulus);
  unsigned char* buffer = malloc(sizeof(unsigned char) * (*len));
  BN_bn2bin(modulus, buffer);

  RSA_free(rsa);
  EVP_PKEY_free(key);

  return buffer;
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
  client_cert_t* cert = (client_cert_t*)SSL_get_ex_data(ssl, client_cert_index);

  if (cert != NULL && !cert->initialized) {
    // set this flag so that we don't perform this logic multiple times (leading
    // to memory leaks when re-allocating the fingerprint needlessly)
    //
    // i tried to work around this with SSL_VERIFY_CLIENT_ONCE and depth=0, but
    // apparently OpenSSL has other plans and it isn't telling me what they are;
    // so we have to do this
    cert->initialized = true;

    size_t pubkey_len = 0;
    hash_buffer_256_t hash;
    unsigned char* modulus = get_modulus_from_x509(x509, &pubkey_len);
    size_t hash_len = compute_sha256_hash(&hash, modulus, pubkey_len);
    free(modulus);

    // allocate space for each hash byte to be illustrated as 2 characters, plus
    // a null terminator
    const size_t fingerprint_len = hash_len * 2;
    cert->fingerprint = malloc((fingerprint_len + 1) * sizeof(char));
    if (cert->fingerprint == NULL) {
      LOG_ERROR("Failed to allocate space for certificate fingerprint");
      return 0;
    }

    for (int i = 0; i < hash_len; ++i) {
      snprintf(&cert->fingerprint[i], 2, "%02x", hash.data[i]);
    }

    cert->fingerprint[fingerprint_len] = '\0';
    cert->not_after = get_x509_expiration(x509);
  }

  return 1;
}
