package com.enonic.xp.app.oidcjwtidprovider;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.RSAKeyProvider;

public class RSAAlgorithmProvider
{
    private final RSAKeyProvider rsaKeyProvider;

    public RSAAlgorithmProvider( final RSAKeyProvider rsaKeyProvider )
    {
        this.rsaKeyProvider = rsaKeyProvider;
    }

    public Algorithm getAlgorithm( final String algorithm )
        throws Exception
    {
        switch ( algorithm )
        {
            case "RS256":
                return Algorithm.RSA256( rsaKeyProvider );
            case "RS384":
                return Algorithm.RSA384( rsaKeyProvider );
            case "RS512":
                return Algorithm.RSA512( rsaKeyProvider );
            default:
                throw new Exception( "Invalid algorithm " + algorithm );
        }
    }
}
