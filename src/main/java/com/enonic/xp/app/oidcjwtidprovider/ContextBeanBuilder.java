package com.enonic.xp.app.oidcjwtidprovider;

import com.enonic.xp.security.PrincipalKey;

public class ContextBeanBuilder
{
    private String principalKey;

    public void setPrincipalKey( final String principalKey )
    {
        this.principalKey = principalKey;
    }

    public ContextBean build()
    {
        return new ContextBean( PrincipalKey.from( principalKey ) );
    }
}
