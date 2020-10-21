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
        let user = authLib.getPrincipal("user:" + portalLib.getIdProviderKey() + ":" + userName);

        if (user) {
            log.debug("Found user '%s'", userName);
        } else if (idProviderConfig.create_users) {
            try {
                log.debug("User '%s' not found creating...", userName);
                user = authLib.createUser({
                    idProvider: portalLib.getIdProviderKey(),
                    name: userName,
                    displayName: getDisplayName(idProviderConfig, payload),
                    email: getEmail(idProviderConfig, payload)
                });
            } catch (err) {
                const errAsString = "" + err;
                log.debug("Error creating user '%s':", userName, errAsString)

                if (errAsString.startsWith('com.enonic.xp.security.PrincipalAlreadyExistsException')) {
                    // This happens because of a race condition, another process just created the user
                    user = authLib.getPrincipal("user:" + portalLib.getIdProviderKey() + ":" + userName);
                } else {
                    log.warning("User '%s' could not be provided: %s", userName, errAsString);
                }
            }
        }

        return user;
    });

    let scope = 'REQUEST';
    if (idProviderConfig.create_session) {
        scope = 'SESSION';
    }

    if (user) {
        log.debug("Logging in user '%s'", user.login);
        authLib.login({
            user: user.login,
            idProvider: portalLib.getIdProviderKey(),
            skipAuth: true,
            scope: scope
        });
    } else {
        log.debug("User not found!");
    }
};