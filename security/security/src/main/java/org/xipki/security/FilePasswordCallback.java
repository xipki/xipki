/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.security;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

import org.xipki.common.util.IoUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.security.api.PasswordCallback;
import org.xipki.security.api.PasswordResolverException;

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

        String passwordHint = null;
        BufferedReader reader = null;
        try
        {
            reader = new BufferedReader(new FileReader(IoUtil.expandFilepath(passwordFile)));
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
            throw new PasswordResolverException("Could not read file " + passwordFile, e);
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
            throw new PasswordResolverException("No password is specified in file " + passwordFile);
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
    public void init(String conf)
    throws PasswordResolverException
    {
        if(StringUtil.isBlank(conf))
        {
            throw new PasswordResolverException("conf could not be null or empty");
        }
        passwordFile = IoUtil.expandFilepath(conf);
    }
}
