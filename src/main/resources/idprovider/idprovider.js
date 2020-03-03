const jwt = require('/lib/jwt');
const users = require('/lib/users');
const oidc = require('/lib/oidc');

exports.autoLogin = function (req) {
    log.debug("JWT autologin");

    let handler = jwt.getJwtHandler({
        wellKnownEndpoint: oidc.wellKnownEndpoint()
    });

    let token = handler.validate(jwt.extractToken(req), oidc.allowedSubjects());

    if (!token.valid) {
        log.debug("JWT token invalid: " + token.message);
        return;
    }

    log.debug("JWT token valid, getting user");
    users.login(token.payload);
};