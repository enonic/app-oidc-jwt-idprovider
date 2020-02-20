function required(params, name) {
    var value = params[name];
    if (value === undefined) {
        throw 'Parameter \'' + name + '\' is required';
    }
    return value;
}

function ContextHandler(native) {
    this.bean = native;
}

ContextHandler.prototype.setContext = function () {
    this.bean.setContext();
};

exports.getContextHandler = function (options) {
    var builder = __.newBean('com.enonic.xp.app.oidcjwtidprovider.ContextBeanBuilder');

    builder.principalKey = required(options, "principalKey");

    return new ContextHandler(builder.build());
};