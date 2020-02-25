package com.enonic.app.oidcjwtidprovider;

import com.enonic.xp.testing.ScriptRunnerSupport;

public class JwtHandlerScriptTest
    extends ScriptRunnerSupport
{
    @Override
    public String getScriptTestFile()
    {
        return "/test/jwt-test.js";
    }
}