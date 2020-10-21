const authLib = require('/lib/xp/auth');
const jwt = require('/lib/jwt');
const users = require('/lib/users');
const oidc = require('/lib/oidc');

exports.autoLogin = function (req) {
    log.debug("JWT autologin");

    let handler = jwt.getJwtHandler({
        wellKnownEndpoint: oidc.wellKnownEndpoint()
    });

    let extracted_token = jwt.extractToken(req);
    if (!extracted_token) {
        return;
    }

    let token = handler.validate(extracted_token, oidc.allowedSubjects());
    if (!token.valid) {
        log.debug("JWT token invalid: " + token.message);
        return;
    }

    log.debug("JWT token valid, getting user");
    users.login(token.payload);
};

exports.logout = function (req) {
    authLib.logout();

    var redirectUrl = req.validTicket ? req.params.redirect : undefined;

    if (redirectUrl) {
        return {
            redirect: redirectUrl
        };
    } else {
        return {
            contentType: 'application/json',
            body: JSON.stringify({'message': 'Logged out!'})
        };
    }
}