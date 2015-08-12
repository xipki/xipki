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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

import org.xipki.common.util.StringUtil;
import org.xipki.password.api.PasswordCallback;
import org.xipki.password.api.PasswordResolverException;

/**
 * @author Lijun Liao
 */

public class FilePasswordCallback implements PasswordCallback
{
    private String passwordFile;

    @Override
    public char[] getPassword(
            final String prompt)
    throws PasswordResolverException
    {
        if(passwordFile == null)
        {
            throw new PasswordResolverException("please initialize me first");
        }

        String passwordHint = null;
        BufferedReader reader = null;
        try
        {
            reader = new BufferedReader(new FileReader(expandFilepath(passwordFile)));
            String line;
            while((line = reader.readLine()) != null)
            {
                line = line.trim();
                if(StringUtil.isNotBlank(line) && line.startsWith("#") == false)
                {
                    passwordHint = line;
                    break;
                }
            }
        }catch(IOException e)
        {
            throw new PasswordResolverException("could not read file " + passwordFile, e);
        }finally
        {
            if(reader != null)
            {
                try
                {
                    reader.close();
                }catch(IOException e)
                {
                }
            }
        }

        if(passwordHint == null)
        {
            throw new PasswordResolverException("no password is specified in file " + passwordFile);
        }

        if(StringUtil.startsWithIgnoreCase(passwordHint, OBFPasswordResolver.__OBFUSCATE))
        {
            return OBFPasswordResolver.deobfuscate(passwordHint).toCharArray();
        }
        else
        {
            return passwordHint.toCharArray();
        }
    }

    @Override
    public void init(
            final String conf)
    throws PasswordResolverException
    {
        if(StringUtil.isBlank(conf))
        {
            throw new PasswordResolverException("conf could not be null or empty");
        }
        passwordFile = expandFilepath(conf);
    }

    private static String expandFilepath(
            final String path)
    {
        if (path.startsWith("~" + File.separator))
        {
            return System.getProperty("user.home") + path.substring(1);
        }
        else
        {
            return path;
        }
    }

}
