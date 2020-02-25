/**
 * Functions to get/create users based on JWT claims.
 *
 * @example
 * const user = require('/lib/user');
 *
 * @module user
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

/**
 * This function get or creates user based on JWT token payload
 *
 * @param {object} params Input parameters as JSON.
 * @param {object} params.idProviderConfig Configuration of the OIDC JWT id provider
 * @param {object} params.payload JWT token payload
 *
 * @returns {string} Principal key of user.
 */
exports.getOrCreateUser = function (params) {
    const idProviderConfig = required(params, "idProviderConfig")
    const payload = required(params, "payload")

    const userId = payload[idProviderConfig.userName_claim];

    return runAsSu(function () {

        log.debug("Searching for user '%s'", userId);
        const user = authLib.getPrincipal("user:" + portalLib.getIdProviderKey() + ":" + userId);

        if (user) {
            log.debug("Found user '%s'", userId);
            return user.key;
        }

        const displayName = payload[idProviderConfig.userDisplayName_claim]

        log.debug("User '%s' not found creating...", userId);
        return authLib.createUser({
            idProvider: portalLib.getIdProviderKey(),
            name: userId,
            displayName: displayName
        }).key;
    });
};