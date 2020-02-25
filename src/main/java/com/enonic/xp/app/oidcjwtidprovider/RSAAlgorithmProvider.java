package com.enonic.xp.app.oidcjwtidprovider;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.apache.commons.lang.NotImplementedException;

import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.RSAKeyProvider;

public class RSAAlgorithmProvider
{
    private final RSAKeyProvider rsaKeyProvider;

    public RSAAlgorithmProvider( final JwkProvider jwkProvider )
    {
        this.rsaKeyProvider = new RSAKeyProviderMapper( jwkProvider );
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

    private class RSAKeyProviderMapper
        implements RSAKeyProvider
    {
        private final JwkProvider jwkProvider;

        public RSAKeyProviderMapper( final JwkProvider jwkProvider )
        {
            this.jwkProvider = jwkProvider;
        }

        @Override
        public RSAPublicKey getPublicKeyById( final String keyId )
        {
            try
            {
                return (RSAPublicKey) jwkProvider.get( keyId ).getPublicKey();
            }
            catch ( JwkException e )
            {
                e.printStackTrace();
                throw new RuntimeException( e.getMessage(), e );
            }
        }

        @Override
        public RSAPrivateKey getPrivateKey()
        {
            throw new NotImplementedException( "Should not be called" );
        }

        @Override
        public String getPrivateKeyId()
        {
            throw new NotImplementedException( "Should not be called" );
        }
    }
}
