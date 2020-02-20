package com.enonic.xp.app.oidcjwtidprovider;

import com.enonic.xp.context.Context;
import com.enonic.xp.context.ContextAccessor;
import com.enonic.xp.context.ContextBuilder;
import com.enonic.xp.security.PrincipalKey;
import com.enonic.xp.security.RoleKeys;
import com.enonic.xp.security.User;
import com.enonic.xp.security.auth.AuthenticationInfo;

public class ContextBean
{
    private final PrincipalKey principalKey;

    public ContextBean( final PrincipalKey principalKey )
    {
        this.principalKey = principalKey;
    }

    public void setContext()
    {
        ContextAccessor.INSTANCE.set( createContext() );
    }

    private Context createContext()
    {
        // TODO: Add the users roles to the context
        final AuthenticationInfo authInfo = AuthenticationInfo.create().
            principals( RoleKeys.AUTHENTICATED, principalKey ).
            user( User.create().key( principalKey ).
                login( principalKey.getId() ).
                build() ).
            build();
        return ContextBuilder.from( ContextAccessor.current() ).
            authInfo( authInfo ).
            build();
    }
}
