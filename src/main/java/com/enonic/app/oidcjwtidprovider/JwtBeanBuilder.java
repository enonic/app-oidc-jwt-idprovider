package com.enonic.app.oidcjwtidprovider;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URL;
import java.net.URLConnection;
import java.util.Map;
import java.util.concurrent.ExecutionException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.auth0.jwk.JwkProviderBuilder;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

public class JwtBeanBuilder
{
    private static final Logger log = LoggerFactory.getLogger( JwtBeanBuilder.class );

    private static final int TIMEOUT_MS = 5000;

    private static final Cache<String, JwtBean> JWT_HANDLER_CACHE = CacheBuilder.newBuilder().build();

    private String wellKnownEndpoint;

    public void setWellKnownEndpoint( final String wellKnownEndpoint )
    {
        this.wellKnownEndpoint = wellKnownEndpoint;
    }

    public JwtBean build()
        throws ExecutionException
    {
        return JWT_HANDLER_CACHE.get( wellKnownEndpoint, () -> newJwtBean( wellKnownEndpoint ) );
    }

    private static JwtBean newJwtBean( final String wellKnownEndpoint )
        throws IOException
    {
        log.debug( "Initializing OIDC provider" );
        var wellKnown = getWellKnownEndpoint( wellKnownEndpoint );
        var jwkProvider = new JwkProviderBuilder( new URL( (String) wellKnown.get( "jwks_uri" ) ) ).cached( true )
            .timeouts( TIMEOUT_MS, TIMEOUT_MS )
            .build();
        return new JwtBean( wellKnown, new JwtHandler( new RSAAlgorithmProvider( jwkProvider ) ) );
    }

    private static Map<String, Object> getWellKnownEndpoint( final String wellKnownEndpoint )
    {
        try
        {
            final URLConnection c = new URL( wellKnownEndpoint ).openConnection();
            c.setConnectTimeout( TIMEOUT_MS );
            c.setReadTimeout( TIMEOUT_MS );

            try (InputStream inputStream = c.getInputStream())
            {
                return new ObjectMapper().readerFor( Map.class ).readValue( inputStream );
            }
        }
        catch ( IOException e )
        {
            throw new UncheckedIOException( e );
        }
    }
}
