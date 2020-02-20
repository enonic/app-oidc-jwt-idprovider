function required(params, name) {
    var value = params[name];
    if (value === undefined) {
        throw 'Parameter \'' + name + '\' is required';
    }
    return value;
}

exports.extractToken = function (req) {
    var authHeader = req.headers["Authorization"];
    if (authHeader && authHeader.startsWith("Bearer ")) {
        return authHeader.replace("Bearer ", "");
    }
    return null
}

function JWTHandler(native) {
    this.bean = native;
}

JWTHandler.prototype.validate = function (jwt) {
    var result = this.bean.getJwtHandler().validate(jwt);
    if (result.valid) {
        result.payload = JSON.parse(result.payload)
    }
    return result;
};

JWTHandler.prototype.wellKnown = function () {
    return this.bean.getWellKnown()
};

exports.getJwtHandler = function (options) {
    var builder = __.newBean('com.enonic.xp.app.oidcjwtidprovider.JwtBeanBuilder');

    builder.wellKnownEndpoint = required(options, "wellKnownEndpoint");

    return new JWTHandler(builder.build());
};

