/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.common;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author Lijun Liao
 */

public class DfltEnvironmentParameterResolver implements
        EnvironmentParameterResolver
{
    private final Map<String, String> envParameters = new ConcurrentHashMap<>();

    public DfltEnvironmentParameterResolver()
    {
    }

    @Override
    public String getParameterValue(String parameterName)
    {
        return envParameters.get(parameterName);
    }

    @Override
    public Set<String> getAllParameterNames()
    {
        return envParameters.keySet();
    }

    public String getEnvParam(String name)
    {
        return envParameters.get(name);
    }

    public void addEnvParam(String name, String value)
    {
        envParameters.put(name, value);
    }

    public void clear()
    {
        envParameters.clear();
    }

    public String removeEnvParam(String envParamName)
    {
        return envParameters.remove(envParamName);
    }

}
