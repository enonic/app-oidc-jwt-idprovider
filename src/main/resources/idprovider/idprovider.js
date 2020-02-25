const authLib = require('/lib/xp/auth');

const jwt = require('/lib/jwt');
const context = require('/lib/context');
const user = require('/lib/user');

function getJwtHandler() {
    return jwt.getJwtHandler({
        wellKnownEndpoint: authLib.getIdProviderConfig().well_known_endpoint
    });
}

exports.autoLogin = function (req) {
    log.debug("JWT autologin");
    const token = getJwtHandler().validate(jwt.extractToken(req));

    let principalKey;
    if (token.valid) {
        log.debug("JWT token valid, getting user");
        principalKey = user.getOrCreateUser({
            idProviderConfig: authLib.getIdProviderConfig(),
            payload: token.payload
        });
    } else {
        log.debug("JWT token invalid: " + token.message);
    }

    log.debug("Setting context for request");
    context.getContextHandler({
        "principalKey": principalKey,
        "jwt": token,
    }).setContext();
};

exports.handle401 = function (req) {
    log.debug("Handling 401");
    let jwt = context.getContextHandler().getJwt();
    if (!jwt.valid) {
        log.debug("JWT token not valid, returning 401");
        return {
            "status": 401,
            "contentType": "application/json",
            "body": {
                "message": jwt.message,
                "status": 401
            }
        };
    } else {
        log.debug("JWT token valid, returning 403");
        return {
            "status": 403,
            "contentType": "application/json",
            "body": {
                "message": "You don't have permission to access this resource",
                "status": 403
            }
        };
    }
};

