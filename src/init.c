#include <R_ext/Rdynload.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

/*
 * Register OpenSSL routines at package load.
 * The name of this function should always match the package name.
 */
void R_init_GoogleAPI(DllInfo *info) {
  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_algorithms();
}

/*
 * Free all OpenSSL resources at package unload.
 * The name of this function should always match the package name.
 */
void R_unload_GoogleAPI(DllInfo *info) {
  EVP_cleanup();
  ERR_free_strings();
}

