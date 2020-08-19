/**
 * Functions to handle validation of JWT tokens
 *
 * @example
 * const jwt = require('/lib/jwt');
 *
 * @module jwt
 */

function required(params, name) {
    var value = params[name];
    if (value === undefined) {
        throw 'Parameter \'' + name + '\' is required';
    }
    return value;
}

/**
 * This function extracts token from HTTP request headers
 *
 * @param {object} req HTTP request
 *
 * @returns {string} JWT token
 */
exports.extractToken = function (req) {
    let authHeader = req.headers["Authorization"];
    log.debug("Extracting 'Authorization' header: " + authHeader);
    if (authHeader) {
        log.debug("'Authorization' header found");

        if (authHeader.startsWith("Bearer ")) {
            log.debug("'Authorization' header starts with 'Bearer', extracting token");
            return authHeader.replace("Bearer ", "");
        } else {
            log.debug("'Authorization' header does not start with 'Bearer '");
        }
    }

    let queryParam = req.params['jwt'];
    log.debug("Extracting query param 'jwt': " + queryParam);
    if (queryParam) {
        log.debug("Query param 'jwt' found");
        return queryParam;
    }

    let wsSecProtoHeader = req.headers["Sec-WebSocket-Protocol"];
    log.debug("Extracting 'Sec-WebSocket-Protocol' header: " + wsSecProtoHeader);
    if (wsSecProtoHeader) {
        log.debug("'Sec-WebSocket-Protocol' header found");
        let matches = wsSecProtoHeader.match(/jwt,\s\S+\.\S+\.\S+/g);
        if (matches.length == 1) {
            log.debug("'Sec-WebSocket-Protocol' header contains token");
            return matches[0].replace("jwt, ", "");
        }
    }

    log.debug("Unable to extract JWT token");
    return null;
};

function JWTHandler(native) {
    this.bean = native;
}

/**
 * This function validates JWT token with JWT handler.
 *
 * @param {object} jwt JWT token
 *
 * @returns {object} Result of JWT validation
 */
JWTHandler.prototype.validate = function (jwt, allowedAudence) {
    let aud = allowedAudence;
    if (!aud) {
        aud = [];
    } else if (!Array.isArray(aud)) {
        aud = [aud];
    }
    return this.bean.getJwtHandler().validate(jwt, aud);
};

/**
 * This function returns the well known configuration of OIDC provider
 *
 * @returns {object} Well known configuration
 */
JWTHandler.prototype.wellKnown = function () {
    return this.bean.getWellKnown()
};

/**
 * This function creates a new JWT handler for OIDC provider
 *
 * @param {object} params Input parameters as JSON.
 * @param {object} params.wellKnownEndpoint Well known endpoint of provider
 *
 * @returns {object} JWT Handler
 */
exports.getJwtHandler = function (params) {
    var builder = __.newBean('com.enonic.app.oidcjwtidprovider.JwtBeanBuilder');

    builder.wellKnownEndpoint = required(params, "wellKnownEndpoint");

    return new JWTHandler(builder.build());
};

