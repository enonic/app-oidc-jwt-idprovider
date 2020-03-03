const authLib = require('/lib/xp/auth');

exports.wellKnownEndpoint = function () {
    return authLib.getIdProviderConfig().oidc_well_known_endpoint;
};

exports.allowedSubjects = function () {
    return authLib.getIdProviderConfig().validation_allowed_subjects;
};