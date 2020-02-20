package com.enonic.xp.app.oidcjwtidprovider;

import java.net.URL;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import com.auth0.jwk.GuavaCachedJwkProvider;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.interfaces.RSAKeyProvider;

public class CachedRSAKeyProvider
    implements RSAKeyProvider
{
    private final JwkProvider jwkProvider;

    public CachedRSAKeyProvider( final URL jwksUrl )
    {
        this.jwkProvider = new GuavaCachedJwkProvider( new UrlJwkProvider( jwksUrl ) );
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
            throw new RuntimeException( e.getMessage(), e );
        }
    }

    @Override
    public RSAPrivateKey getPrivateKey()
    {
        throw new RuntimeException( "Should not be called" );
    }

    @Override
    public String getPrivateKeyId()
    {
        throw new RuntimeException( "Should not be called" );
    }
}
