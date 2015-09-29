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

package org.xipki.common.util;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Lijun Liao
 */

public class IoUtil
{
    private IoUtil()
    {
    }

    public static void closeStream(
    		final OutputStream stream)
    {
        if (stream == null)
        {
            return;
        }
        try
        {
            stream.close();
        } catch (Throwable t)
        {
        }
    }
    public static byte[] read(
            final String fileName)
    throws IOException
    {
        return read(new File(expandFilepath(fileName)));
    }

    public static byte[] read(
            final File file)
    throws IOException
    {
        return read(new FileInputStream(expandFilepath(file)));
    }

    public static byte[] read(
            final InputStream in)
    throws IOException
    {
        try
        {
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            int readed = 0;
            byte[] buffer = new byte[2048];
            while ((readed = in.read(buffer)) != -1)
            {
                bout.write(buffer, 0, readed);
            }

            return bout.toByteArray();
        } finally
        {
            if (in != null)
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

    public static void save(
            final String fileName,
            final byte[] encoded)
    throws IOException
    {
        save(new File(expandFilepath(fileName)), encoded);
    }

    public static void save(
            final File pFile,
            final byte[] content)
    throws IOException
    {
        File file = expandFilepath(pFile);

        File parent = file.getParentFile();
        if (parent != null && !parent.exists())
        {
            parent.mkdirs();
        }

        FileOutputStream out = new FileOutputStream(file);
        try
        {
            out.write(content);
        } finally
        {
            out.close();
        }
    }

    public static byte[] leftmost(
            final byte[] bytes,
            final int bitCount)
    {
        int byteLenKey = (bitCount + 7) / 8;

        if (bitCount >= (bytes.length << 3))
        {
            return bytes;
        }

        byte[] truncatedBytes = new byte[byteLenKey];
        System.arraycopy(bytes, 0, truncatedBytes, 0, byteLenKey);

        if (bitCount % 8 > 0) // shift the bits to the right
        {
            int shiftBits = 8 - (bitCount % 8);

            for (int i = byteLenKey - 1; i > 0; i--)
            {
                truncatedBytes[i] = (byte) (
                        (byte2int(truncatedBytes[i]) >>> shiftBits)
                        | ((byte2int(truncatedBytes[i - 1]) << (8 - shiftBits)) & 0xFF));
            }
            truncatedBytes[0] = (byte) (byte2int(truncatedBytes[0]) >>> shiftBits);
        }

        return truncatedBytes;
    }

    private static int byte2int(
            final byte b)
    {
        return (b >= 0)
                ? b
                : 256 + b;
    }

    public static String getHostAddress()
    throws SocketException
    {
        List<String> addresses = new LinkedList<>();

        Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
        while (interfaces.hasMoreElements())
        {
            NetworkInterface n = (NetworkInterface) interfaces.nextElement();
            Enumeration<InetAddress> ee = n.getInetAddresses();
            while (ee.hasMoreElements())
            {
                InetAddress i = (InetAddress) ee.nextElement();
                if (i instanceof Inet4Address)
                {
                    addresses.add(((Inet4Address) i).getHostAddress());
                }
            }
        }

        for (String addr : addresses)
        {
            if (!addr.startsWith("192.") && !addr.startsWith("127."))
            {
                return addr;
            }
        }

        for (String addr : addresses)
        {
            if (!addr.startsWith("127."))
            {
                return addr;
            }
        }

        if (addresses.size() > 0)
        {
            return addresses.get(0);
        } else
        {
            try
            {
                return InetAddress.getLocalHost().getHostAddress();
            } catch (UnknownHostException e)
            {
                return "UNKNOWN";
            }
        }
    }

    public static String expandFilepath(
            final String path)
    {
        if (path.startsWith("~" + File.separator))
        {
            return System.getProperty("user.home") + path.substring(1);
        } else
        {
            return path;
        }
    }

    public static File expandFilepath(
            final File file)
    {
        String path = file.getPath();
        String expandedPath = expandFilepath(path);
        if (path.equals(expandedPath))
        {
            return file;
        } else
        {
            return new File(expandedPath);
        }
    }

    public static String convertSequenceName(
            final String sequenceName)
    {
        StringBuilder sb = new StringBuilder();
        int n = sequenceName.length();
        for (int i = 0; i < n; i++)
        {
            char c = sequenceName.charAt(i);
            if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))
            {
                sb.append(c);
            } else
            {
                sb.append("_");
            }
        }
        return sb.toString();
    }

    public static String base64Encode(
            final byte[] data,
            final boolean withLineBreak)
    {

        String b64Str = Base64.encodeToString(data, Base64.NO_WRAP);
        if (!withLineBreak)
        {
            return b64Str;
        }

        if (b64Str.length() < 64)
        {
            return b64Str;
        }

        StringBuilder sb = new StringBuilder();
        final int blockSize = 64;
        final int size = b64Str.length();

        final int nFullBlock = size / blockSize;

        for (int i = 0; i < nFullBlock; i++)
        {
            int offset = i * blockSize;
            sb.append(b64Str.subSequence(offset, offset + blockSize)).append("\n");
        }

        if (size % blockSize != 0)
        {
            sb.append(b64Str.substring(nFullBlock * blockSize)).append("\n");
        }
        sb.deleteCharAt(sb.length() - 1);
        return sb.toString();
    }
}
