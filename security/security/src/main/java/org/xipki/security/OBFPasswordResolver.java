/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security;

import java.nio.charset.StandardCharsets;

import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.api.SinglePasswordResolver;

/**
 * @author Lijun Liao
 */

public class OBFPasswordResolver  implements SinglePasswordResolver
{
    public static final String __OBFUSCATE = "OBF:";

    @Override
    public boolean canResolveProtocol(String protocol)
    {
        return "OBF".equals(protocol);
    }

    @Override
    public char[] resolvePassword(String passwordHint)
    throws PasswordResolverException
    {
        return deobfuscate(passwordHint).toCharArray();
    }

    public static String obfuscate(String s)
    {
        StringBuilder buf = new StringBuilder();
        byte[] b = s.getBytes(StandardCharsets.UTF_8);

        buf.append(__OBFUSCATE);
        for (int i = 0; i < b.length; i++)
        {
            byte b1 = b[i];
            byte b2 = b[b.length - (i + 1)];
            if (b1<0 || b2<0)
            {
                int i0 = (0xff&b1)*256 + (0xff&b2);
                String x = Integer.toString(i0, 36).toLowerCase();
                buf.append("U0000",0,5-x.length());
                buf.append(x);
            }
            else
            {
                int i1 = 127 + b1 + b2;
                int i2 = 127 + b1 - b2;
                int i0 = i1 * 256 + i2;
                String x = Integer.toString(i0, 36).toLowerCase();

                buf.append("000",0,4-x.length());
                buf.append(x);
            }

        }
        return buf.toString();

    }

    /* ------------------------------------------------------------ */
    public static String deobfuscate(String s)
    {
        if (s.startsWith(__OBFUSCATE))
        {
            s = s.substring(4);
        }

        byte[] b = new byte[s.length() / 2];
        int l = 0;
        for (int i = 0; i < s.length(); i += 4)
        {
            if (s.charAt(i)=='U')
            {
                i++;
                String x = s.substring(i, i + 4);
                int i0 = Integer.parseInt(x, 36);
                byte bx = (byte)(i0>>8);
                b[l++] = bx;
            }
            else
            {
                String x = s.substring(i, i + 4);
                int i0 = Integer.parseInt(x, 36);
                int i1 = (i0 / 256);
                int i2 = (i0 % 256);
                byte bx = (byte) ((i1 + i2 - 254) / 2);
                b[l++] = bx;
            }
        }

        return new String(b, 0, l,StandardCharsets.UTF_8);
    }
}
