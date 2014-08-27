/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import org.xipki.security.api.PasswordCallback;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.common.IoCertUtil;

/**
 * @author Lijun Liao
 */

public class FilePasswordCallback implements PasswordCallback
{
    private String passwordFile;

    @Override
    public char[] getPassword(String prompt)
    throws PasswordResolverException
    {
        if(passwordFile == null)
        {
            throw new PasswordResolverException("please initialize me first");
        }

        byte[] content;
        try
        {
            content = IoCertUtil.read(passwordFile);
        }catch(IOException e)
        {
            throw new PasswordResolverException("Could not read file " + passwordFile, e);
        }

        String passwordHint;
        try
        {
            passwordHint = new String(content, "UTF-8");
        } catch (UnsupportedEncodingException e)
        {
            throw new PasswordResolverException("UnsupportedEncodingException: " + e.getMessage(), e);
        }

        if(passwordHint.startsWith(OBFPasswordResolver.__OBFUSCATE))
        {
            return OBFPasswordResolver.deobfuscate(passwordHint).toCharArray();
        }
        else
        {
            return passwordHint.toCharArray();
        }
    }

    @Override
    public void init(String conf)
    throws PasswordResolverException
    {
        if(conf == null || conf.isEmpty())
        {
            throw new PasswordResolverException("conf could not be null or empty");
        }
        passwordFile = IoCertUtil.expandFilepath(conf);
    }
}
