/*
 * Copyright 2014 xipki.org
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

package org.xipki.security;

import java.io.Console;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;

import org.bouncycastle.util.encoders.Base64;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.api.SinglePasswordResolver;

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
                Console console = System.console();
                if(console != null)
                {
                    this.masterPassword = console.readPassword("Please enter the master password\n");
                }
                else
                {
                    JPanel panel = new JPanel();
                    JLabel label = new JLabel("Enter a password:");
                    JPasswordField pass = new JPasswordField(10);
                    panel.add(label);
                    panel.add(pass);
                    String[] options = new String[]{"OK"};
                    int option = JOptionPane.showOptionDialog(null, panel, "Password requried",
                                             JOptionPane.NO_OPTION, JOptionPane.PLAIN_MESSAGE,
                                             null, options, options[0]);
                    if(option == 0) // pressing OK button
                    {
                        this.masterPassword = pass.getPassword();
                    }
                    else
                    {
                        this.masterPassword = null;
                    }
                }
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
