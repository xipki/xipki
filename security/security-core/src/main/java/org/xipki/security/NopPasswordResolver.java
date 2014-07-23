/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security;

import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.PasswordResolverException;

/**
 * @author Lijun Liao
 */

public class NopPasswordResolver implements PasswordResolver
{

    public static NopPasswordResolver INSTANCE = new NopPasswordResolver();

    private NopPasswordResolver()
    {
    }

    public char[] resolvePassword(String passwordHint)
    throws PasswordResolverException
    {
        return passwordHint.toCharArray();
    }
}
