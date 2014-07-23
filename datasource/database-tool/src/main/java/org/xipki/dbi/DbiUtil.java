/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.dbi;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * @author Lijun Liao
 */

public class DbiUtil
{
    public static String buildFilename(String prefix, String suffix,
            int minCertIdOfCurrentFile, int maxCertIdOfCurrentFile, int maxCertId)
    {
        StringBuilder sb = new StringBuilder();
        sb.append(prefix);

        int len = Integer.toString(maxCertId).length();
        String a = Integer.toString(minCertIdOfCurrentFile);
        for(int i = 0; i < len - a.length(); i++)
        {
            sb.append('0');
        }
        sb.append(a);
        sb.append("-");

        String b = Integer.toString(maxCertIdOfCurrentFile);
        for(int i = 0; i < len - b.length(); i++)
        {
            sb.append('0');
        }
        sb.append(b);

        sb.append(suffix);
        return sb.toString();
    }

    public static byte[] read(InputStream in)
    throws IOException
    {
        try
        {
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            int readed = 0;
            byte[] buffer = new byte[1024];
            while ((readed = in.read(buffer)) != -1)
            {
                bout.write(buffer, 0, readed);
            }

            return bout.toByteArray();
        } finally
        {
            try
            {
                in.close();
            } catch (IOException e)
            {
            }
        }
    }
}
