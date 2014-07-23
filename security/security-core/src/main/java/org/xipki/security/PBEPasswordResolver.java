/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.util.encoders.Base64;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.api.SinglePasswordResolver;

/**
 * @author Lijun Liao
 */

public class PBEPasswordResolver implements SinglePasswordResolver
{

    private static final int iterationCount = 2000;

    private char[] masterPassword;
    private final Object masterPasswordLock = new Object();

    protected char[] getMasterPassword()
    {
        synchronized (masterPasswordLock)
        {
            if(masterPassword == null)
            {
                this.masterPassword = SecurePasswordInputPanel.readPassword("Please enter the master password");
            }
            return masterPassword;
        }
    }

    public void clearMasterPassword()
    {
        masterPassword = null;
    }

    public PBEPasswordResolver()
    {
    }

    @Override
    public boolean canResolveProtocol(String protocol)
    {
        return "PBE".equalsIgnoreCase(protocol);
    }

    @Override
    public char[] resolvePassword(String passwordHint)
    throws PasswordResolverException
    {
        return resolvePassword(getMasterPassword(), passwordHint);
    }

    public static char[] resolvePassword(char[] masterPassword, String passwordHint)
    throws PasswordResolverException
    {
        byte[] bytes = Base64.decode(passwordHint.substring("PBE:".length()));
        int n = bytes.length;
        if(n <= 16 && n != 0)
        {
            throw new PasswordResolverException("invalid length of the encrypted password");
        }

        byte[] salt = Arrays.copyOf(bytes, 16);
        byte[] cipherText = Arrays.copyOfRange(bytes, 16, n);

        byte[] pwd;
        try
        {
            pwd = PasswordBasedEncryption.decrypt(cipherText, masterPassword, iterationCount, salt);
        } catch (GeneralSecurityException e)
        {
            throw new PasswordResolverException("could not decrypt the password: " + e.getMessage());
        }

        char[] ret = new char[pwd.length];
        for(int i = 0; i < pwd.length; i++)
        {
            ret[i] = (char) pwd[i];
        }

        return ret;
    }

    public static String encryptPassword(char[] masterPassword, char[] password)
    throws PasswordResolverException
    {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        byte[] encrypted;
        try
        {
            encrypted = PasswordBasedEncryption.encrypt(new String(password).getBytes(),
                    masterPassword, iterationCount, salt);
        } catch (GeneralSecurityException e)
        {
            throw new PasswordResolverException("could not encrypt the password: " + e.getMessage());
        }

        byte[] encryptedWithSalt = new byte[salt.length + encrypted.length];
        System.arraycopy(salt, 0, encryptedWithSalt, 0, salt.length);
        System.arraycopy(encrypted, 0, encryptedWithSalt, salt.length, encrypted.length);
        String pbeText = "PBE:" + Base64.toBase64String(encryptedWithSalt);
        return pbeText;
    }

}
