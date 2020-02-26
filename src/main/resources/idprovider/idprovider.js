const authLib = require('/lib/xp/auth');

const jwt = require('/lib/jwt');
const context = require('/lib/context');
const user = require('/lib/user');

function getJwtHandler() {
    return jwt.getJwtHandler({
        wellKnownEndpoint: authLib.getIdProviderConfig().oidc_well_known_endpoint
    });
}

function allowedSubjects() {
    return authLib.getIdProviderConfig().validation_allowed_subjects;
}

exports.autoLogin = function (req) {
    log.debug("JWT autologin");
    const token = getJwtHandler().validate(jwt.extractToken(req), allowedSubjects());

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

    log.debug("Setting context for request with principalKey: " + principalKey);
    context.getContextHandler({
        "principalKey": principalKey,
        "jwt": token,
    }).setContext();
};

exports.handle401 = function (req) {
    let jwt = context.getContextHandler().getJwt();
    log.debug("Returning 401: " + jwt.message);
    return {
        "status": 401,
        "contentType": "application/json",
        "body": {
            "message": jwt.message,
            "status": 401
        }
    };
};

