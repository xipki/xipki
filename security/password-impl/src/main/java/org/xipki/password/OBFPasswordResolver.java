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

import java.nio.charset.StandardCharsets;

import org.xipki.common.util.StringUtil;
import org.xipki.password.api.PasswordResolverException;
import org.xipki.password.api.SinglePasswordResolver;

/**
 * @author Lijun Liao
 */

public class OBFPasswordResolver  implements SinglePasswordResolver
{
    public static final String __OBFUSCATE = "OBF:";

    @Override
    public boolean canResolveProtocol(
            final String protocol)
    {
        return "OBF".equalsIgnoreCase(protocol);
    }

    @Override
    public char[] resolvePassword(
            final String passwordHint)
    throws PasswordResolverException
    {
        return deobfuscate(passwordHint).toCharArray();
    }

    public static String obfuscate(
            final String s)
    {
        StringBuilder buf = new StringBuilder();
        byte[] b = s.getBytes(StandardCharsets.UTF_8);

        buf.append(__OBFUSCATE);
        for (int i = 0; i < b.length; i++)
        {
            byte b1 = b[i];
            byte b2 = b[b.length - (i + 1)];
            if (b1 < 0 || b2 < 0)
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
    public static String deobfuscate(
            String s)
    {
        if (StringUtil.startsWithIgnoreCase(s, __OBFUSCATE))
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
