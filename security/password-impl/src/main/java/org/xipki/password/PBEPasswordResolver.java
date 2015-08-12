/*
 * Copyright (c) 2015 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.password;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

import org.xipki.common.util.Base64;
import org.xipki.common.util.StringUtil;
import org.xipki.password.api.PasswordCallback;
import org.xipki.password.api.PasswordResolverException;
import org.xipki.password.api.SinglePasswordResolver;

/**
 * @author Lijun Liao
 */

public class PBEPasswordResolver implements SinglePasswordResolver
{

    private static final int iterationCount = 2000;

    private char[] masterPassword;
    private final Object masterPasswordLock = new Object();
    private PasswordCallback masterPwdCallback;

    protected char[] getMasterPassword()
    throws PasswordResolverException
    {
        synchronized (masterPasswordLock)
        {
            if(masterPassword == null)
            {
                if(masterPwdCallback == null)
                {
                    throw new PasswordResolverException("masterPasswordCallback is not initialized");
                }
                this.masterPassword = masterPwdCallback.getPassword("Please enter the master password");
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
    public boolean canResolveProtocol(
            final String protocol)
    {
        return "PBE".equalsIgnoreCase(protocol);
    }

    @Override
    public char[] resolvePassword(
            final String passwordHint)
    throws PasswordResolverException
    {
        return resolvePassword(getMasterPassword(), passwordHint);
    }

    public static char[] resolvePassword(
            final char[] masterPassword,
            final String passwordHint)
    throws PasswordResolverException
    {
        byte[] bytes = Base64.decode(passwordHint.substring("PBE:".length()), Base64.DEFAULT);
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

    public static String encryptPassword(
            final char[] masterPassword,
            final char[] password)
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
        String pbeText = "PBE:" + Base64.encodeToString(encryptedWithSalt, Base64.NO_WRAP);
        return pbeText;
    }

    public void setMasterPasswordCallback(
            String masterPasswordCallback)
    {
        if(masterPasswordCallback == null)
        {
            return;
        }

        masterPasswordCallback = masterPasswordCallback.trim();
        if(StringUtil.isBlank(masterPasswordCallback))
        {
            return;
        }

        String className;
        String conf = null;

        int delimIndex = masterPasswordCallback.indexOf(' ');
        if(delimIndex == -1)
        {
            className = masterPasswordCallback;
        }
        else
        {
            className = masterPasswordCallback.substring(0, delimIndex);
            conf = masterPasswordCallback.substring(delimIndex + 1);
        }

        try
        {
            Class<?> clazz = Class.forName(className);
            Object obj = clazz.newInstance();
            if(obj instanceof PasswordCallback)
            {
                ((PasswordCallback) obj).init(conf);
                this.masterPwdCallback = (PasswordCallback) obj;
            }
            else
            {
                throw new IllegalArgumentException("invalid masterPasswordCallback configuration " + masterPasswordCallback);
            }

        }catch(Exception e)
        {
            throw new IllegalArgumentException("invalid masterPasswordCallback configuration " + masterPasswordCallback
                    + ", " + e.getClass().getName() + ": " + e.getMessage());
        }
    }

}
