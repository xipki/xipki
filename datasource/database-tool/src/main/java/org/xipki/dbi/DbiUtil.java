/*
 * Copyright (c) 2014 xipki.org
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

package org.xipki.dbi;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

class DbiUtil
{
    static String buildFilename(String prefix, String suffix,
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
