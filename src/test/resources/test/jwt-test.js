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
    assert.assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA256withRSA", res.message);

    var res = jwtHandler.validate(
        "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6Ijc2MmZhNjM3YWY5NTM1OTBkYjhiYjhhNjM2YmYxMWQ0MzYwYWJjOTgifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.fkVEwd9LijkldkOr1Dr6w3W-Z6mFL6yKieGzejsiEz_abNhKOGQO4wFIXOF6DCQ1L6mX5ZrYTr7OL-zastA_Dc39SegjedRzPJtRZy53fxiwPiq_spJqvmSzdZoTx395dEy9LNd925wYyxCbukjSOGJjDIQeSm-iZ2TLPVHjjGvmFr0Oy6efYqPMCc0yKQIskfMARFeztC_vXm3cll7Rd_OVCGWL7G8Wae7Cs-N4z8ZYZZaE-1gVUH9gM4HQriUD_gQ3_vmhgfaWt-H4xDEnCoPqN5L3PiXTfIRetNDeHMUqfWJFqX1mwBx1rUQjjLK33GVRrNUPetvmEmRG2WEztg");
    assert.assertEquals(401, res.code);
    assert.assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA384withRSA", res.message);

    var res = jwtHandler.validate(
        "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6Ijc2MmZhNjM3YWY5NTM1OTBkYjhiYjhhNjM2YmYxMWQ0MzYwYWJjOTgifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.k9Eh-3KntpUhMd4Rh6mdaTkgwxTutDf4ClFMpJmuB3AhPX1qZRfDzboCE0PAKuEYBlhllIEXpjDnrEYE3k7lcnAOnrFCqKUtzAdcN2ijpjhS67qQTxZVTwU71JhVA3ght4E8gsyqnruO7qLtjcA-cd0OY0ZRoI6QR7IsNRLOJqFgaQgwePnanXHn_IJVA-O7I06FRfcAE4zPZ_s007LTiPCsoGP76wjSLnJPffO_Td1yzNrXOptgW7z7aP5mQT7-4SmzNu_E1MQRIE2j2zGzFSHX8KXdsGjq5RIbIv5m6q8LbcdbzCJD926Lt07ZEC9GaZ5Xkvg3qQ4NoSvELLDbHg");
    assert.assertEquals(401, res.code);
    assert.assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA512withRSA", res.message);
};