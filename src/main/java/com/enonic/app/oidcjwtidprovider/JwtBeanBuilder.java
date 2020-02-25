package com.enonic.app.oidcjwtidprovider;

import java.util.concurrent.ExecutionException;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

public class JwtBeanBuilder
{
    private static Cache<String, JwtBean> jwtHandlerCache = CacheBuilder.newBuilder().build();

    private String wellKnownEndpoint;

    public void setWellKnownEndpoint( final String wellKnownEndpoint )
    {
        this.wellKnownEndpoint = wellKnownEndpoint;
    }

    public JwtBean build()
        throws ExecutionException
    {
        return jwtHandlerCache.get( wellKnownEndpoint, () -> new JwtBean( wellKnownEndpoint ) );
    }
}
