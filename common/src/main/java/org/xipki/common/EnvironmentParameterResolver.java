/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.common;

import java.util.Set;

/**
 * @author Lijun Liao
 */

public interface EnvironmentParameterResolver
{

    Set<String> getAllParameterNames();
    String getParameterValue(String parameterName);

}
