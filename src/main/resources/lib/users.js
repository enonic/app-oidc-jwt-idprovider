/**
 * Functions to login users based on JWT claims.
 *
 * @example
 * const user = require('/lib/users');
 *
 * @module users
 */

const contextLib = require('/lib/xp/context');
const authLib = require('/lib/xp/auth');
const portalLib = require('/lib/xp/portal');

function required(params, name) {
    var value = params[name];
    if (value === undefined) {
        throw 'Parameter \'' + name + '\' is required';
    }
    return value;
}

function runAsSu(callback) {
    return contextLib.run({
        user: {
            login: 'su',
            idProvider: 'system'
        },
        principals: ['role:system.admin']
    }, callback);
}

function sanitizeUserName(userName) {
    return userName.replace(/[|\\\/?*]/gi, '_');
}

/**
 * This function get or creates user based on JWT token payload and logs in as that user.
 *
 * @param {object} payload JWT payload
 */
exports.login = function (payload) {
    const idProviderConfig = authLib.getIdProviderConfig();
    const userId = sanitizeUserName(required(payload, idProviderConfig.claim_username));

    let user = runAsSu(function () {
        log.debug("Searching for user '%s'", userId);
        const user = authLib.getPrincipal("user:" + portalLib.getIdProviderKey() + ":" + userId);

        if (user) {
            log.debug("Found user '%s'", userId);
            return user.login;
        }

        const displayName = payload[idProviderConfig.claim_displayname];
        const email = payload[idProviderConfig.claim_email];

        log.debug("User '%s' not found creating...", userId);
        return authLib.createUser({
            idProvider: portalLib.getIdProviderKey(),
            name: userId,
            displayName: displayName,
            email: email
        }).login;
    });

    log.debug("Logging in user '%s'", user);
    authLib.login({
        user: user,
        idProvider: portalLib.getIdProviderKey(),
        skipAuth: true,
        scope: 'REQUEST'
    });
};