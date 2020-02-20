package com.enonic.xp.app.oidcjwtidprovider;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

public class JwtHandler
{
    private final RSAAlgorithmProvider rsaAlgorithmProvider;

    private final Base64.Decoder decode = Base64.getDecoder();

    public JwtHandler( RSAAlgorithmProvider rsaAlgorithmProvider )
    {
        this.rsaAlgorithmProvider = rsaAlgorithmProvider;
    }

    public Object validate( final String jwt )
    {
        DecodedJWT decodedJwt = null;
        try
        {
            decodedJwt = JWT.decode( jwt );
        }
        catch ( JWTDecodeException e )
        {
            return handleFailure( null, 401, "Invalid JWT token format" );
        }

        Algorithm algorithm = null;
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
        catch ( JWTVerificationException e )
        {
            return handleFailure( decodedJwt, 401, e.getMessage() );
        }

        return handleSuccess( decodedJwt );
    }

    private Map<String, Object> handlePayload( final DecodedJWT jwt )
    {
        Map<String, Object> res = new HashMap<>();
        if ( jwt != null )
        {
            res.put( "payload", new String( decode.decode( jwt.getPayload() ) ) );
        }
        else
        {
            res.put( "payload", null );
        }
        return res;
    }

    private Object handleSuccess( final DecodedJWT jwt )
    {
        Map<String, Object> res = handlePayload( jwt );
        res.put( "valid", true );
        res.put( "message", "ok" );
        res.put( "code", 200 );
        return res;
    }

    private Object handleFailure( final DecodedJWT jwt, Integer code, String message )
    {
        Map<String, Object> res = handlePayload( jwt );
        res.put( "message", message );
        res.put( "code", code );
        res.put( "valid", false );
        return res;
    }
}
