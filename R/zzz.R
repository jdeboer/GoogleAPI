## Package constants
DEFAULT_CACHE_PATH <- ".google-oauth-cache"
DEFAULT_LOG_FILE <- "google-debug.log"
DEFAULT_OOB_VALUE <- FALSE

## Google API default values
GOOGLE_AUTH_SERVER_URI <- "https://accounts.google.com/o/oauth2/auth"
GOOGLE_TOKEN_SERVER_URI <- "https://accounts.google.com/o/oauth2/token"
GOOGLE_AUTH_REVOKE_URI <- "https://accounts.google.com/o/oauth2/revoke"
GOOGLE_AUTH_VALIDATE_URI <- "https://www.googleapis.com/oauth2/v1/tokeninfo"
GOOGLE_AUTH_CERT_URL <- "https://www.googleapis.com/oauth2/v1/certs"
GOOGLE_OOB_REDIRECT_URIS <- c("urn:ietf:wg:oauth:2.0:oob", "http://localhost") ## Currently not used.
GOOGLE_CLIENT_CERT_URL_PREFIX <- "https://www.googleapis.com/robot/v1/metadata/x509/"

## Service related constants
GOOGLE_DISCOVERY_KIND <- "discovery#restDescription"
GOOGLE_DISCOVERY_VERSION <- "v1"

## Google Compute Engine related constants
GOOGLE_COMPUTE_METADATA_HEADERS <- c("X-Google-Metadata-Request: True")
GOOGLE_COMPUTE_METADATA_EMAIL_URI <- "http://metadata/computeMetadata/v1/instance/service-accounts/{name}/email"
GOOGLE_COMPUTE_METADATA_SCOPES_URI <- "http://metadata/computeMetadata/v1/instance/service-accounts/{name}/scopes"
GOOGLE_COMPUTE_METADATA_TOKEN_URI <- "http://metadata/computeMetadata/v1/instance/service-accounts/{name}/token"

## Messages
## TODO(siddharthab): Put these in the localization framework.
MESSAGE_PACKAGE_UPDATE <- "The current version of this service is not compatible with this R package. Please update the package or contact support."
MESSAGE_GOOGLE_COMPUTE_INCORRECT_SCOPE <- "You are running on Google Compute Engine but correct scopes have not been set for this VM instance."
MESSAGE_GOOGLE_COMPUTE_SUCCESS <- "Obtained OAuth token for the API from Google Compute Engine."

service <- NULL
.onLoad <- function(libname, pkgname) {
    ## Cache file relative to working directory, or NULL if no cache.
    options("google_oauth_cache"=DEFAULT_CACHE_PATH)
    
    # Logical. Setting this option to null will fall back to httr option.
    options("google_oauth_oob"=DEFAULT_OOB_VALUE);
    
    ## Logical. Set this to TRUE to memoise API calls up to a certain memory limit.
    options("google_api_memoise"=FALSE) ## Currently not supported.
    
    ## Set this to a connection object to output generated code for the API.
    options("google_api_debug"=file(DEFAULT_LOG_FILE, open="w"))
}

.onAttach <- function(libname, pkgname) {
    if (DEFAULT_OOB_VALUE) {
      packageStartupMessage(paste0("Default browser ", 
          ifelse(is.character(getOption("browser")), 
              paste0(getOption("browser"), " "),
              ""),
          "will be used for obtaining OAuth credentials for a different user.\n",
          "Set options(\"google_oauth_oob\"=TRUE) to not use a browser."))
    }
}

.onUnload <- function(libpath) {
    debugCon <- getOption("google_api_debug")
    if (!is.null(debugCon) && inherits(debugCon, "connection") && isOpen(debugCon)) {
        close(debugCon)
    }
}
