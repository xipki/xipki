/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security;

import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;

import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.api.SinglePasswordResolver;

/**
 * @author Lijun Liao
 */

public class PasswordResolverImpl implements PasswordResolver
{
    private ConcurrentLinkedQueue<SinglePasswordResolver> resolvers = new ConcurrentLinkedQueue<>();

    public PasswordResolverImpl()
    {
    }

    public void setPasswordResolvers(List<SinglePasswordResolver> resolvers)
    {
        this.resolvers = new ConcurrentLinkedQueue<SinglePasswordResolver>(resolvers);
    }

    public void removePasswordResolver(SinglePasswordResolver resolver)
    {
        resolvers.remove(resolver);
    }

    public char[] resolvePassword(String passwordHint)
    throws PasswordResolverException
    {
        int index = passwordHint.indexOf(':');
        if(index == -1)
        {
            return passwordHint.toCharArray();
        }

        String protocol = passwordHint.substring(0, index);

        for(SinglePasswordResolver resolver : resolvers)
        {
            if(resolver.canResolveProtocol(protocol))
            {
                return resolver.resolvePassword(passwordHint);
            }
        }

        return passwordHint.toCharArray();
    }

}
