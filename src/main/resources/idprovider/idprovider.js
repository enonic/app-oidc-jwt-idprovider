const authLib = require('/lib/xp/auth');
const jwt = require('/lib/jwt');
const context = require('/lib/context');
const user = require('/lib/user');

function getJwtHandler() {
    return jwt.getJwtHandler({
        wellKnownEndpoint: authLib.getIdProviderConfig().well_known_endpoint
    });
}

function handleToken(req) {
    var token = jwt.extractToken(req);
    if (!token) {
        return null;
    }
    return getJwtHandler().validate(token);
}

exports.handle401 = function (req) {
    const tokenResult = handleToken(req);
    if (!tokenResult) {
        // Could not get token
        return {
            "status": 401,
            "contentType": "application/json",
            "body": {
                "code": 401,
                "message": "Missing JWT access token"
            }
        };
    } else if (tokenResult.valid) {
        // Token is valid but this user cannot access this resource
        return {
            "status": 401,
            "contentType": "application/json",
            "body": {
                "code": 401,
                "message": "You are not allowed to access this resource"
            }
        };
    } else {
        // Token verification failed
        return {
            "status": tokenResult.code,
            "contentType": "application/json",
            "body": {
                "code": tokenResult.code,
                "message": tokenResult.message
            }
        };
    }
};

exports.autoLogin = function (req) {
    var tokenResult = handleToken(req);

    if (!tokenResult || !tokenResult.valid) {
        // Token is not valid
        return;
    }

    // Get user and set context
    context.getContextHandler({
        "principalKey": user.getOrCreateUser(authLib.getIdProviderConfig(), tokenResult).key
    }).setContext();
};