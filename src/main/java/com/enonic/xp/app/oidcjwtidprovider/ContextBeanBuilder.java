package com.enonic.xp.app.oidcjwtidprovider;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

import com.enonic.xp.script.bean.BeanContext;
import com.enonic.xp.script.bean.ScriptBean;
import com.enonic.xp.security.PrincipalKey;
import com.enonic.xp.security.SecurityService;

public class ContextBeanBuilder
    implements ScriptBean
{
    private Supplier<SecurityService> securityService;

    private String principalKey;

    private Map<String, Object> jwt;

    public void setPrincipalKey( final String principalKey )
    {
        this.principalKey = principalKey;
    }

    public void setJwt( final Map<String, Object> jwt )
    {
        this.jwt = jwt;
    }

    public ContextBean build()
    {
        PrincipalKey rPk = principalKey == null ? null : PrincipalKey.from( principalKey );
        Map<String, Object> rJwt = jwt == null ? new HashMap<>() : jwt;
        return new ContextBean( securityService.get(), rPk, rJwt );
    }

    @Override
    public void initialize( final BeanContext context )
    {
        this.securityService = context.getService( SecurityService.class );
    }
}
