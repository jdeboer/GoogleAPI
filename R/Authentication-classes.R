# Can only be used with public datasets.
setClass("PublicAPIKey",
    representation(
        key="character"
    ),
    validity=function(object) {
        if (length(object@key) == 0) {
            "Key missing."
        } else {
            TRUE
        }
    }
)
setMethod("show", "PublicAPIKey", function(object) {
    cat("<public_api_key>\n", sep = "")
    cat("  key: ", "<hidden>", "\n", sep = "")
})

## We allow httr::Token2.0 and PublicAPIKey as valid credentials for Google API.
setClassUnion("GoogleCredential", c("Token2.0", "PublicAPIKey"))

setClass("GoogleOAuthParams",
    representation(
        scopes="character",
        "VIRTUAL"
    )
)

setClass("GoogleClientSecrets", contains="GoogleOAuthParams",
    representation(
        clientId="character", # Unique Key
        authUri="character",
        tokenUri="character",
        "VIRTUAL"
    ),
    prototype(
        authUri=GOOGLE_AUTH_SERVER_URI,
        tokenUri=GOOGLE_TOKEN_SERVER_URI
    ),
    validity=function(object) {
        if (length(object@tokenUri) == 0) {
            "Token URI is absent."
        } else if (nchar(object@tokenUri) == 0) {
            "Token URI is empty."
        } else 
            TRUE
    }
)

setClass("UserOAuth", contains="GoogleClientSecrets",
    representation(
        clientSecret="character",
        redirectUris="character", ## Currently not used.
        authCertUrl="character",
        validateUri="character",
        revokeUri="character"
    ),
    prototype(
        redirectUris=GOOGLE_OOB_REDIRECT_URIS,
        authCertUrl=GOOGLE_AUTH_CERT_URL,
        validateUri=GOOGLE_AUTH_VALIDATE_URI,
        revokeUri=GOOGLE_AUTH_REVOKE_URI
    ),
    validity=function(object) {
        if (length(object@clientId) == 0) {
            "Client ID missing."
        } else if (length(object@clientSecret) == 0) {
            "Client Secret missing."
        } else {
            TRUE
        }
    }
)
setMethod("show", "UserOAuth", function(object) {
    cat("<user_oauth_params>\n", sep = "")
    cat("  clientId: ", object@clientId, "\n", sep = "")
    cat("  secret: ", "<hidden>", "\n", sep = "")
    cat("  scopes: ", paste(object@scopes, collapse=', '), "\n", sep = "")
})

setClass("ServerOAuth", contains="GoogleClientSecrets",
    representation(
        clientEmail="character",
        privateKeyId="character", # Public key fingerprint
        privateKey="character", # PKCS#8 private key
        pkcs12="raw" # PKCS#12 binary contents
    ),
    validity=function(object) {
        pkcs8Present <- length(object@privateKey) > 0
        pkcs12Present <- length(object@pkcs12) > 0
        if (length(object@clientEmail) == 0) {
            "Client Email missing."
        }
        else if (!xor(pkcs8Present, pkcs12Present)) {
            "Exactly one of PKCS#8 or PKCS#12 keys must be specified."
        } else {
            TRUE
        }
    }
)
setMethod("show", "ServerOAuth", function(object) {
    cat("<server_oauth_params>\n", sep = "")
    cat("  clientEmail: ", object@clientEmail, "\n", sep = "")
    if (length(object@privateKeyId) > 0) {
        cat("  privateKeyId: ", object@privateKeyId, "\n", sep = "")
    }
    if (length(object@privateKey) > 0) {
        cat("  privateKey: ", "<hidden>", "\n", sep = "")
    } else if (length(object@pkcs12) > 0) {
        cat("  p12: ", "<hidden>", "\n", sep = "")
    }
    cat("  scopes: ", paste(object@scopes, collapse=', '), "\n", sep = "")
})

setClass("GCEOAuth", contains="GoogleOAuthParams",
    representation(
        name="character"
    ),
    prototype(
        name="default"
    ),
    validity=function(object) {
        if (length(object@name) == 0) {
            "Service Account name (email) missing."
        } else {
            TRUE
        }
    }
)
setMethod("show", "GCEOAuth", function(object) {
    cat("<gce_oauth_params>\n", sep = "")
    cat("  name: ", object@name, "\n", sep = "")
    cat("  scopes: ", paste(object@scopes, collapse=', '), "\n", sep = "")
})

## Inherit the reference class httr::Token2.0 and override methods for more correctness.
## Do not use this class directly.
GoogleOAuthToken <- setRefClass("GoogleOAuthToken", contains = "Token2.0",
    methods = list(
        sign = function(method, url) {
            if (params$as_header) {
                config <- add_headers(Authorization =
                        paste(credentials$token_type, credentials$access_token))
                list(url = url, config = config)
            } else {
                url <- parse_url(url)
                url$query$oauth_token <- credentials$access_token ## Different from Token 2.0
                list(url = build_url(url), config = config())
            }
        }
    )
)

## TODO(siddharthab): Make user OAuth tokens also inherit from this class.
## See https://github.com/hadley/httr/issues/113
UserToken <- getRefClass("Token2.0", where = asNamespace("httr"))

## Note that this class uses the S4 GoogleOAuthParams instead of httr::oauth.app
ServerToken <- setRefClass("ServerToken", field = c("app" = "GoogleOAuthParams"), contains = "GoogleOAuthToken",
    methods = list(
        init_credentials = function() {
            credentials <<- getServerToken(app)
        },
        can_refresh = function() {
            TRUE
        },
        refresh = function() {
            credentials <<- getServerToken(app)
            .self
        },
        cache = function() {
            .self ## No-op
        },
        load_from_cache = function() {
            FALSE
        }
    )
)

## Note that this class uses the S4 GoogleOAuthParamss instead of httr::oauth.app
GCEToken <- setRefClass("GCEToken", field = c("app" = "GoogleOAuthParams"), contains = "GoogleOAuthToken",
    methods=list(
        init_credentials = function() {
            credentials <<- getGCEToken(app)
        },
        can_refresh = function() {
            TRUE
        },
        refresh = function() {
            credentials <<- getGCEToken(app)
            .self
        },
        cache = function() {
            .self ## No-op
        },
        load_from_cache = function() {
            FALSE
        }
    )
)