/**
 * Functions to handle context of requests
 *
 * @example
 * const context = require('/lib/context');
 *
 * @module context
 */

function ContextHandler(native) {
    this.bean = native;
}

/**
 * This function sets requests context for the context handler user
 */
ContextHandler.prototype.setContext = function () {
    this.bean.setContext();
};

/**
 * This function returns JWT validation results from context
 *
 * @returns {object} JWT validation results
 */
ContextHandler.prototype.getJwt = function () {
    return this.bean.getJwt();
};

/**
 * This function creates a new context handler
 *
 * @param {object} params Input parameters as JSON.
 * @param {object} params.principalKey Principal key of user that the context should be set to
 * @param {object} params.jwt JWT validation results to put in context attributes
 *
 * @returns {object} Context handler
 */
exports.getContextHandler = function (options) {
    let builder = __.newBean('com.enonic.xp.app.oidcjwtidprovider.ContextBeanBuilder');

    if (options) {
        if (options.principalKey) {
            builder.principalKey = options.principalKey;
        }

        if (options.jwt) {
            builder.jwt = options.jwt;
        }
    }

    return new ContextHandler(builder.build());
};