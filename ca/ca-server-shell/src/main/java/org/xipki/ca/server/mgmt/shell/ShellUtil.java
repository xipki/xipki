/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 Lijun Liao
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

package org.xipki.ca.server.mgmt.shell;

import org.bouncycastle.util.encoders.Base64;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.common.ConfPairs;
import org.xipki.security.common.IoCertUtil;

/**
 * @author Lijun Liao
 */

class ShellUtil
{
    static String canonicalizeSignerConf(String keystoreType, String signerConf,
            PasswordResolver passwordResolver)
    throws Exception
    {
        if(signerConf.contains("file:") == false && signerConf.contains("base64:") == false )
        {
            return signerConf;
        }

        ConfPairs confPairs = new ConfPairs(signerConf);
        String keystoreConf = confPairs.getValue("keystore");
        String passwordHint = confPairs.getValue("password");
        String keyLabel     = confPairs.getValue("key-label");

        if(passwordHint == null)
        {
            throw new IllegalArgumentException("password is not set in " + signerConf);
        }

        byte[] keystoreBytes;
        if(keystoreConf.startsWith("file:"))
        {
            String keystoreFile = keystoreConf.substring("file:".length());
            keystoreBytes = IoCertUtil.read(keystoreFile);
        }
        else if(keystoreConf.startsWith("base64:"))
        {
            keystoreBytes = Base64.decode(keystoreConf.substring("base64:".length()));
        }
        else
        {
            return signerConf;
        }

        char[] password;
        if(passwordResolver == null)
        {
            password = passwordHint.toCharArray();
        }
        else
        {
            password = passwordResolver.resolvePassword(passwordHint);
        }

        keystoreBytes = IoCertUtil.extractMinimalKeyStore(keystoreType,
                keystoreBytes, keyLabel, password);

        confPairs.putPair("keystore", "base64:" + Base64.toBase64String(keystoreBytes));
        return confPairs.getEncoded();
    }

}
