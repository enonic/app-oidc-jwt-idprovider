var assert = require('/lib/xp/testing');
var jwtLib = require('/lib/jwt');

exports.testJWT = function () {
    // Init cache
    jwtLib.getJwtHandler({
        wellKnownEndpoint: "https://accounts.google.com/.well-known/openid-configuration"
    });

    var jwtHandler = jwtLib.getJwtHandler({
        wellKnownEndpoint: "https://accounts.google.com/.well-known/openid-configuration"
    });

    assert.assertEquals("https://accounts.google.com", jwtHandler.wellKnown().issuer);

    var res = jwtHandler.validate(
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ijc2MmZhNjM3YWY5NTM1OTBkYjhiYjhhNjM2YmYxMWQ0MzYwYWJjOTgifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.YUhU7xNP2tE9hE_ZPdkHsLDDeLzx5SLfeqGCwODq7ogAOMbMM5lx6NTSI1H5ywKXuff0SGcchnj6P-7C50MN2owElPASVMkpYi7s1Xjivlbi-Jty0ix7AYUT8PcN_04Bsme7Jx0DoYrkv9PObuw3mXX3YsP_unSpldUlnwrjM547upN8POYjFS5KlWyuQLtmRY1jJLclq2fUgPjk2i-oI4E3QlbLlL1ylCcOIwufvhFXs28asSnzaudyqFWxKgxcKIOqid1FN2lk2izONnTXNuUX5tSz0iYqh5O7-tlj5-6hUMG_rGlGNI0EG6YLMgmvUrnja_sicAkHII78MsPEtA");

    assert.assertEquals(401, res.code);
    assert.assertEquals("Failed to get key with kid 762fa637af953590db8bb8a636bf11d4360abc98", res.message);

    var res = jwtHandler.validate(
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ijc2MmZhNjM3YWY5NTM1OTBkYjhiYjhhNjM2YmYxMWQ0MzYwYWJjOTgifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.YUhU7xNP2tE9hE_ZPdkHsLDDeLzx5SLfeqGCwODq7ogAOMbMM5lx6NTSI1H5ywKXuff0SGcchnj6P-7C50MN2owElPASVMkpYi7s1Xjivlbi-Jty0ix7AYUT8PcN_04Bsme7Jx0DoYrkv9PObuw3mXX3YsP_unSpldUlnwrjM547upN8POYjFS5KlWyuQLtmRY1jJLclq2fUgPjk2i-oI4E3QlbLlL1ylCcOIwufvhFXs28asSnzaudyqFWxKgxcKIOqid1FN2lk2izONnTXNuUX5tSz0iYqh5O7-tlj5-6hUMG_rGlGNI0EG6YLMgmvUrnja_sicAkHII78MsPEtA",
        ["fakesub"]);

    assert.assertEquals(401, res.code);
    assert.assertEquals("Token subject not allowed", res.message);
};