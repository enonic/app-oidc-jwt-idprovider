package com.enonic.app.oidcjwtidprovider;

import java.util.Map;
import java.util.concurrent.Callable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.enonic.xp.context.ContextAccessor;
import com.enonic.xp.context.ContextBuilder;
import com.enonic.xp.security.PrincipalKey;
import com.enonic.xp.security.PrincipalKeys;
import com.enonic.xp.security.RoleKeys;
import com.enonic.xp.security.SecurityService;
import com.enonic.xp.security.User;
import com.enonic.xp.security.auth.AuthenticationInfo;

public class ContextBean
{
    private static final Logger log = LoggerFactory.getLogger( ContextBean.class );

    private static final String ATTRIBUTE_JWT_KEY = "jwt";

    private final SecurityService securityService;

    private final PrincipalKey principalKey;

    private final Map<String, Object> jwt;

    public ContextBean( final SecurityService securityService, final PrincipalKey principalKey, final Map<String, Object> jwt )
    {
        this.securityService = securityService;
        this.principalKey = principalKey;
        this.jwt = jwt;
    }

    public Object getJwt()
    {
        return ContextAccessor.current().getAttribute( ATTRIBUTE_JWT_KEY );
    }

    public void setContext()
    {
        log.debug( "Building new context with '" + ATTRIBUTE_JWT_KEY + "' attribute" );
        ContextBuilder cb = ContextBuilder.from( ContextAccessor.current() ).
            attribute( ATTRIBUTE_JWT_KEY, jwt );

        if ( principalKey != null )
        {
            log.debug( "Principal key provided, adding to context" );
            PrincipalKeys memberships = runAsRoot( () -> securityService.getAllMemberships( principalKey ) );

            AuthenticationInfo auth = AuthenticationInfo.create().
                principals( principalKey ).
                principals( memberships ).
                user( User.create().key( principalKey ).
                    login( principalKey.getId() ).
                    build() ).
                build();
            log.debug( "Request principals: " + auth.getPrincipals() );

            cb.authInfo( auth );
        }
        else
        {
            log.debug( "No Principal key provided" );
        }

        ContextAccessor.INSTANCE.set( cb.build() );
    }

    private <T> T runAsRoot( Callable<T> callable )
    {
        return ContextBuilder.from( ContextAccessor.current() ).
            authInfo( AuthenticationInfo.create().
                user( User.ANONYMOUS ).
                principals( RoleKeys.ADMIN ).
                build() ).
            build().
            callWith( callable );
    }
}
