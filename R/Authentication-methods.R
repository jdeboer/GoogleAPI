parseUserOAuthClientSecrets <- function(secrets) {
    object <- new("UserOAuth",
        clientId=secrets$client_id,
        clientSecret=secrets$client_secret
    )
    
    # Override defaults with non-empty values from json file.
    authUri <- secrets$auth_uri
    tokenUri <- secrets$token_uri
    redirectUris <- secrets$redirect_uris
    authCertUrl <- secrets$auth_provider_x509_cert_url
    if (!is.null(authUri) && nchar(authUri) > 0) {
        object@authUri <- authUri
    }
    if (!is.null(tokenUri) && nchar(tokenUri) > 0) {
        object@tokenUri <- tokenUri
    }
    if (!is.null(redirectUris) && nchar(redirectUris) > 0) {
        object@redirectUris <- redirectUris
    }
    if (!is.null(authCertUrl) && nchar(authCertUrl) > 0) {
        object@authCertUrl <- authCertUrl
    }
    
    # Check validity and return.
    stopifnot(validObject(object))
    return(object)
}

parseServerOAuthClientSecrets <- function(secrets) {
    object <- new("ServerOAuth",
        clientId=secrets$client_id,
        clientEmail=secrets$client_email,
        privateKeyId=secrets$private_key_id,
        privateKey=secrets$private_key
    )
    
    # Check validity and return
    stopifnot(validObject(object))
    return(object)
}

#' Return a copy of the client GoogleOAuthParams object with the scopes set as provided.
setScopes <- function(oauthParams, scopes) {
  stopifnot(inherits(oauthParams, "GoogleOAuthParams"))
  oauthParams@scopes <- scopes
  return(oauthParams)
}

#' Read client secrets from supplied JSON file or text string, and adding the scopes as supplied.
readClientSecrets <- function(file, scopes) {
    json <- fromJSON(file)
    if (!is.null(json$installed)) {
        secrets <- parseUserOAuthClientSecrets(json$installed)
    } else if (!is.null(json$type) && json$type == "service_account") {
        secrets <- parseServerOAuthClientSecrets(json)
    } else {
        stop("Invalid JSON for client secrets.")
    }
    return(setScopes(secrets, scopes))
}

#' Convenience method for creating user OAuth credentials.
newUserOAuthParams <- function(clientId, clientSecret, scopes) {
    object <- new("UserOAuth",
        clientId=clientId,
        clientSecret=clientSecret,
        scopes=scopes
    )
    
    # Check validity and return.
    stopifnot(validObject(object))
    return(object)
}

newServerOAuthParams <- function(clientEmail, privateKey, scopes) {
    object <- new("ServerOAuth",
        clientEmail=clientEmail,
        privateKey=privateKey,
        scopes=scopes
    )
    
    # Check validity and return.
    stopifnot(validObject(object))
    return(object)
}

newServerOAuthParamsP12 <- function(clientEmail, p12File, scopes) {
    object <- new("ServerOAuth",
        clientEmail=clientEmail,
        pkcs12=readBin(p12File, what=raw(0), n=10*1024),
        scopes=scopes
    )
    
    # Check validity and return.
    stopifnot(validObject(object))
    return(object)
}

getServerToken <- function(clientSecrets) {
    # Utility functions
    b64EncodeUrlSafe <- function(message) {
        chartr('+/', '-_', base64encode(message))
    }
    createClaimSet <- function() {
        currTime <- as.integer(as.POSIXct(Sys.time()))
        claimSet <- list()
        claimSet$iss <- clientSecrets@clientEmail
        claimSet$scope <- paste(clientSecrets@scopes, collapse=' ')
        claimSet$aud <- clientSecrets@tokenUri
        claimSet$exp <- as.integer(currTime + 3600)
        claimSet$iat <- currTime
        
        b64EncodeUrlSafe(charToRaw(toJSON(claimSet, auto_unbox=TRUE)))
    }
    
    # The message header and claimset.
    header <- '{"alg":"RS256","typ":"JWT"}'
    headerB64 <- b64EncodeUrlSafe(charToRaw(header))
    claimSetB64 <- createClaimSet()
    
    # Sign using SHA-256
    message <- paste(headerB64, claimSetB64, sep='.')
    if (length(clientSecrets@privateKey > 0)) {
        key <- .Call(loadPrivateKey, clientSecrets@privateKey)
    } else {
        key <- .Call(loadPKCS12, clientSecrets@pkcs12)
    }
    signature <- b64EncodeUrlSafe(.Call(signRSA, message, key))
    
    # Append the signature and send it across.
    payload <- paste(message, signature, sep='.')
  
    res <- POST(url=clientSecrets@tokenUri, body=list(grant_type="urn:ietf:params:oauth:grant-type:jwt-bearer", assertion=payload))

    # Extract the JSON credentials.
    creds <- content(res, type="application/json")

    stopifnot(!is.null(creds$access_token))
    return(creds)
}

getGCEToken <- function(clientSecrets) {
    scrub <- function(url) {
        sub('{name}', clientSecrets@name, url, fixed=TRUE)
    }
    
    getGCEMetadataConfig <- function() {
        headerPairs <- strsplit(GOOGLE_COMPUTE_METADATA_HEADERS,': ')
        headers <- sapply(headerPairs, '[', 2)
        names(headers) <- sapply(headerPairs, '[', 1)
        return(add_headers(headers))
    }
    
    getGCEScopes <- function() {
        getScopesHelper <- function() {
            res <- GET(scrub(GOOGLE_COMPUTE_METADATA_SCOPES_URI), getGCEMetadataConfig())
            stop_for_status(res) ## Treat DNS and HTTP failures equally.
            strsplit(content(res, as="text"), '\n')[[1]]
        }
        tryCatch(getScopesHelper(), error=function(e) NULL, silent=TRUE)
    }
    
    checkGCEScopes <- function(scopes) {
        return(all(clientSecrets@scopes %in% scopes))
    }
    
    getTokenHelper <- function() {
        res <- GET(scrub(GOOGLE_COMPUTE_METADATA_TOKEN_URI), getGCEMetadataConfig())
        stop_for_status(res) ## Treat DNS and HTTP failures equally.
        message(MESSAGE_GOOGLE_COMPUTE_SUCCESS)
        creds <- content(res, type="application/json")
        stopifnot(!is.null(creds$access_token))
        return(creds)
    }
    
    scopes <- getGCEScopes()
    if (is.null(scopes)) {
        return(NULL) ## Not running in a GCE instance; fail silently.
    } else if(!checkGCEScopes(scopes)) {
        message(MESSAGE_GOOGLE_COMPUTE_INCORRECT_SCOPE)
        return(NULL) ## Message the user and then fail gracefully.
    } else {
        return(tryCatch(getTokenHelper(),
            error=function(e) NULL,
            silent=TRUE))
    }
}

checkCachePath <- function(cachePath) {
    if (!is.character(cachePath)) {
        if (!is.null(cachePath)) {
            warning("Invalid OAuth cache file specified; will not cache objects.")
        }
        return(NULL)
    }
    cachePath <- cachePath[1]
    isDir <- file.info(cachePath)$isdir
    if (!is.na(isDir) && isDir) {
        cachePath <- file.path(cachePath, DEFAULT_CACHE_PATH)
    }
    
    if (file.exists(cachePath)) {
        if (file.access(cachePath, mode=2) < 0) {
            warning(paste("Cache file", cachePath, "present but not writable; will not cache objects."))
            return(NULL)
        } else {
            return(cachePath)
        }
    }
    
    if (file.access(dirname(cachePath), mode=2) < 0) {
        warning("Cache file absent and parent directory not writable; will not cache objects.")
        return(NULL)
    }
    return(cachePath)
}

checkToken <- function(tokenObj) {
    stopifnot(inherits(tokenObj, "Token2.0"))
  
    if (!is.null(tokenObj$credentials)) {
        return(tokenObj)
    } else {
        stop("Invalid token obtained.")
    }
}

setGeneric("getOAuthToken", function(clientSecrets){
    standardGeneric("getOAuthToken")
})

setMethod("getOAuthToken", signature(clientSecrets="UserOAuth"), function(clientSecrets) {
    app <- oauth_app("google", clientSecrets@clientId, clientSecrets@clientSecret)
    
    endpoint <- oauth_endpoint(
        authorize = clientSecrets@authUri,
        access = clientSecrets@tokenUri,
        validate = clientSecrets@validateUri,
        revoke = clientSecrets@revokeUri
    )

    params <- list(scope = clientSecrets@scopes, type = NULL,
        use_oob = getOption("google_oauth_oob"), as_header = TRUE)

    cache_path <- checkCachePath(getOption("google_oauth_cache"))
    
    checkToken(UserToken(app = app, endpoint = endpoint, params = params,
        cache_path = cache_path)$init())
})

setMethod("getOAuthToken", signature(clientSecrets="ServerOAuth"), function(clientSecrets) {
    endpoint <- NULL
    params <- list(scope = NULL, type = NULL, use_oob = NULL, as_header = TRUE)
    
    cache_path <- checkCachePath(getOption("google_oauth_cache"))
    
    checkToken(ServerToken(app = clientSecrets, endpoint = endpoint, params = params,
        cache_path = cache_path)$init())
})

setMethod("getOAuthToken", signature(clientSecrets="GCEOAuth"), function(clientSecrets) {
    endpoint <- NULL
    params <- list(scope = NULL, type = NULL, use_oob = NULL, as_header = TRUE)
    
    cache_path <- checkCachePath(getOption("google_oauth_cache"))
    
    checkToken(GCEToken(app = clientSecrets, endpoint = endpoint, params = params,
        cache_path = cache_path)$init())
})

.primaryAuth <- new.env()
setPrimaryAuth <- function(googleCredential) {
    stopifnot(inherits(googleCredential, "GoogleCredential"))
    
    .primaryAuth$credential <- googleCredential
}

getPrimaryAuth <- function() {
    .primaryAuth$credential
}