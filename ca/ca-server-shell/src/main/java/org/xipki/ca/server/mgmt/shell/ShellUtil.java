/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.shell;

import org.bouncycastle.util.encoders.Base64;
import org.xipki.common.CmpUtf8Pairs;
import org.xipki.common.IoCertUtil;
import org.xipki.security.api.PasswordResolver;

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

        CmpUtf8Pairs utf8Pairs = new CmpUtf8Pairs(signerConf);
        String keystoreConf = utf8Pairs.getValue("keystore");
        String passwordHint = utf8Pairs.getValue("password");
        String keyLabel     = utf8Pairs.getValue("key-label");

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

        utf8Pairs.putUtf8Pair("keystore", "base64:" + Base64.toBase64String(keystoreBytes));
        return utf8Pairs.getEncoded();
    }

}
