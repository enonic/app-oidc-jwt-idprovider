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
    return userName.replace(/[|@\\\/?*]/gi, '-');
}

function getUsername(idProviderConfig, payload) {
    let userName = payload[idProviderConfig.claim_username];
    if (userName === undefined) {
        userName = required(payload, 'sub');
    }
    return sanitizeUserName(userName);
}

function getDisplayName(idProviderConfig, payload) {
    let displayName = payload[idProviderConfig.claim_displayname];
    if (displayName === undefined) {
        displayName = required(payload, 'sub');
    }
    return displayName;
}

function getEmail(idProviderConfig, payload) {
    let email = payload[idProviderConfig.claim_email];
    if (email === undefined) {
        email = getUsername(idProviderConfig, payload) + "@serviceaccount.enonic";
    }
    return email;
}

/**
 * This function get or creates user based on JWT token payload and logs in as that user.
 *
 * @param {object} payload JWT payload
 */
exports.login = function (payload) {
    const idProviderConfig = authLib.getIdProviderConfig();
    const userName = getUsername(idProviderConfig, payload);

    let user = runAsSu(function () {
        log.debug("Searching for user '%s'", userName);
        const user = authLib.getPrincipal("user:" + portalLib.getIdProviderKey() + ":" + userName);

        if (user) {
            log.debug("Found user '%s'", userName);
            return user.login;
        }

        log.debug("User '%s' not found creating...", userName);
        return authLib.createUser({
            idProvider: portalLib.getIdProviderKey(),
            name: userName,
            displayName: getDisplayName(idProviderConfig, payload),
            email: getEmail(idProviderConfig, payload)
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