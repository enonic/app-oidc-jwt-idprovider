package com.enonic.xp.app.oidcjwtidprovider;

import java.io.IOException;
import java.net.URL;
import java.time.Duration;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.ResponseBody;

public class JwtBean
{
    private static final ObjectMapper mapper = new ObjectMapper();

    private final JwtHandler jwtHandler;

    private final Map<String, Object> wellKnown;

    public JwtBean( final String wellKnownEndpoint )
        throws IOException
    {
        this.wellKnown = getWellKnownEndpoint( wellKnownEndpoint );
        this.jwtHandler =
            new JwtHandler( new RSAAlgorithmProvider( new CachedRSAKeyProvider( new URL( (String) wellKnown.get( "jwks_uri" ) ) ) ) );
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> getWellKnownEndpoint( final String wellKnownEndpoint )
        throws IOException
    {
        final Request.Builder request = new Request.Builder();
        request.url( wellKnownEndpoint );
        ResponseBody body = new OkHttpClient().newBuilder().
            callTimeout( Duration.ofSeconds( 5 ) ).
            connectTimeout( Duration.ofSeconds( 5 ) ).
            build().
            newCall( request.build() ).
            execute().
            body();

        return mapper.readValue( body.bytes(), Map.class );
    }

    public Object getWellKnown()
    {
        return wellKnown;
    }

    public JwtHandler getJwtHandler()
    {
        return jwtHandler;
    }
}
