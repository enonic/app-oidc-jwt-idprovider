package com.enonic.xp.app.oidcjwtidprovider;

import java.io.IOException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JwtHandler
{
    private static final Logger log = LoggerFactory.getLogger( JwtHandler.class );

    private static final ObjectMapper mapper = new ObjectMapper();

    private static final Base64.Decoder decode = Base64.getDecoder();

    private final RSAAlgorithmProvider rsaAlgorithmProvider;

    public JwtHandler( RSAAlgorithmProvider rsaAlgorithmProvider )
    {
        this.rsaAlgorithmProvider = rsaAlgorithmProvider;
    }

    public Map<String, Object> validate( final String jwt )
    {
        log.debug( "Validating token: " + jwt );
        if ( jwt == null )
        {
            return handleFailure( null, 401, "Missing JWT access token" );
        }

        DecodedJWT decodedJwt;
        try
        {
            decodedJwt = JWT.decode( jwt );
        }
        catch ( Exception e )
        {
            return handleFailure( null, 401, "Invalid JWT token format" );
        }

        Algorithm algorithm;
        try
        {
            algorithm = rsaAlgorithmProvider.getAlgorithm( decodedJwt.getAlgorithm() );
        }
        catch ( Exception e )
        {
            return handleFailure( decodedJwt, 500, "Unable to setup algorithm" );
        }

        try
        {
            JWT.require( algorithm ).
                acceptLeeway( 1 ).   //1 sec for nbf and iat
                build().
                verify( decodedJwt );
        }
        catch ( Exception e )
        {
            return handleFailure( decodedJwt, 401, e.getMessage() );
        }

        return handleSuccess( decodedJwt );
    }

    private Map<String, Object> handlePayload( final DecodedJWT jwt )
    {
        Map<String, Object> res = new HashMap<>();
        Map payload = null;
        if ( jwt != null )
        {
            try
            {
                payload = getPayload( jwt.getPayload() );
            }
            catch ( IOException e )
            {
                log.warn( "Unable to extract JWT payload" );
            }
        }
        res.put( "payload", payload );
        return res;
    }

    private Map<String, Object> handleSuccess( final DecodedJWT jwt )
    {
        Map<String, Object> res = handlePayload( jwt );
        res.put( "valid", true );
        res.put( "message", "ok" );
        res.put( "code", 200 );
        return res;
    }

    private Map<String, Object> handleFailure( final DecodedJWT jwt, Integer code, String message )
    {
        Map<String, Object> res = handlePayload( jwt );
        res.put( "message", message );
        res.put( "code", code );
        res.put( "valid", false );
        return res;
    }

    private static Map getPayload( String base64Payload )
        throws IOException
    {
        return mapper.readValue( decode.decode( base64Payload ), Map.class );
    }
}
