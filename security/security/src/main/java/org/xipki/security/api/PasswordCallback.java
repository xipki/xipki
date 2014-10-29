/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.api;

/**
 * @author Lijun Liao
 */

public interface PasswordCallback
{
    void init(String conf)
    throws PasswordResolverException;

    char[] getPassword(String prompt)
    throws PasswordResolverException;
}
