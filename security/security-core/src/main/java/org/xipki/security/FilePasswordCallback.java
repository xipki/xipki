/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013-2016 Lijun Liao
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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
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
