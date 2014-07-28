#define USE_RINTERNALS 1
#include <Rinternals.h>

#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>

static const char *pass = "notasecret";

static void free_EVP_PKEY(SEXP ref) {
  EVP_PKEY *key = (EVP_PKEY*) R_ExternalPtrAddr(ref);
  if (key)
    EVP_PKEY_free(key);
}

static SEXP wrap_EVP_PKEY(EVP_PKEY *key) {
  SEXP res = PROTECT(R_MakeExternalPtr(key, R_NilValue, R_NilValue));
  R_RegisterCFinalizerEx(res, free_EVP_PKEY, TRUE);
  setAttrib(res, R_ClassSymbol, mkString("private.key"));
  UNPROTECT(1);
  return res;
}

SEXP loadPrivateKey(SEXP privateKey) {
  EVP_PKEY *key;
  BIO *bio_mem;
  SEXP b64Key;
  
  if (TYPEOF(privateKey) != STRSXP || LENGTH(privateKey) == 0)
    Rf_error("PKCS8 private key must be a character vector of length 1");
  b64Key = STRING_ELT(privateKey, 0);

  bio_mem = BIO_new_mem_buf((void *) CHAR(b64Key), LENGTH(b64Key));
  key = PEM_read_bio_PrivateKey(bio_mem, &key, 0, "Can not ask password.");
  if (!key) {
    Rf_error("%s", ERR_error_string(ERR_get_error(), NULL));
  }
  return wrap_EVP_PKEY(key);
}

SEXP loadPKCS12(SEXP privateKey) {
  EVP_PKEY *key;
  BIO *bio_mem;
  PKCS12 *p12;
  X509 *cert;
  
  if (TYPEOF(privateKey) != RAWSXP)
    Rf_error("PKCS12 private key must be a raw vector");

  bio_mem = BIO_new_mem_buf((void *) RAW(privateKey), LENGTH(privateKey));
  p12 = d2i_PKCS12_bio(bio_mem, &p12);
  if (!p12
    || !PKCS12_verify_mac(p12, pass, strlen(pass))
    || !PKCS12_parse(p12, pass, &key, &cert, NULL)
    || !key) {
    Rf_error("%s", ERR_error_string(ERR_get_error(), NULL));
  }
  return wrap_EVP_PKEY(key);
}

SEXP signRSA(SEXP messageVec, SEXP privateKey) {
  SEXP res;
  SEXP message;
  EVP_MD_CTX *mdctx;
  const EVP_MD *md;
  unsigned char digest[SHA256_DIGEST_LENGTH];
  EVP_PKEY *key;
  RSA *rsa;
  unsigned char sig[8096];
  unsigned int sigLen = 0;

  if (TYPEOF(messageVec) != STRSXP || LENGTH(messageVec) == 0) {
    Rf_error("Payload must be a character vector");
  }
  message = STRING_ELT(messageVec, 0);
  
  md = EVP_sha256();
  mdctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, CHAR(message), LENGTH(message));
  EVP_DigestFinal_ex(mdctx, digest, NULL);
  EVP_MD_CTX_destroy(mdctx);

  if (!inherits(privateKey, "private.key")) {
    Rf_error("Key does not have class private.key");
  }
  key = (EVP_PKEY*) R_ExternalPtrAddr(privateKey);
  if (!key) {
    Rf_error("NULL key provided");
  }
  if (EVP_PKEY_type(key->type) != EVP_PKEY_RSA) {
    Rf_error("Key must be RSA private key");
  }
  rsa = EVP_PKEY_get1_RSA(key);
  if (!rsa) {
    Rf_error("%s", ERR_error_string(ERR_get_error(), NULL));
  }

  if (RSA_sign(NID_sha256, (const unsigned char*) digest, SHA256_DIGEST_LENGTH,
      (unsigned char *) &sig, &sigLen, rsa) != 1) {
    Rf_error("%s", ERR_error_string(ERR_get_error(), NULL));
  }
  res = PROTECT(allocVector(RAWSXP, sigLen));
  memcpy(RAW(res), sig, sigLen);
  UNPROTECT(1);
  return res;
}
