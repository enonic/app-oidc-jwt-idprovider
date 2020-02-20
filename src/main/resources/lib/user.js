const contextLib = require('/lib/xp/context');
const authLib = require('/lib/xp/auth');
const portalLib = require('/lib/xp/portal');

function runAsSu(callback) {
    return contextLib.run({
        user: {
            login: 'su',
            idProvider: 'system'
        },
        principals: ['role:system.admin']
    }, callback);
}

exports.getOrCreateUser = function (idProviderConfig, token) {
    return runAsSu(function () {
        const userId = token.payload[idProviderConfig.userName_claim];
        log.debug("Searching for user '%s'", userId);
        const user = authLib.getPrincipal("user:" + portalLib.getIdProviderKey() + ":" + userId);
        if (!user) {
            log.debug("User '%s' not found creating...", userId);
            return authLib.createUser({
                idProvider: portalLib.getIdProviderKey(),
                name: userId,
                displayName: token.payload[idProviderConfig.userDisplayName_claim]
            });
        } else {
            return user;
            log.debug("Found user '%s'", userId);
        }
    });
}