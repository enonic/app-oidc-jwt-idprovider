package com.enonic.app.oidcjwtidprovider;

import java.io.IOException;
import java.util.Map;

public class JwtBean
{
    private final JwtHandler jwtHandler;

    private final Map<String, Object> wellKnown;

    public JwtBean( final Map<String, Object> wellKnown, final JwtHandler jwtHandler )
        throws IOException
    {
        this.wellKnown = wellKnown;
        this.jwtHandler = jwtHandler;
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
