/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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

package org.xipki.commons.common.util;

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
import java.util.Base64;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class IoUtil {
    private static final Logger LOG = LoggerFactory.getLogger(IoUtil.class);

    private IoUtil() {
    }

    public static void closeStream(
            final OutputStream stream) {
        if (stream == null) {
            return;
        }
        try {
            stream.close();
        } catch (Throwable th) {
            LOG.error("could not close stream: {}", th.getMessage());
        }
    }

    public static byte[] read(
            final String fileName)
    throws IOException {
        return read(new File(expandFilepath(fileName)));
    }

    public static byte[] read(
            final File file)
    throws IOException {
        return read(new FileInputStream(expandFilepath(file)));
    }

    public static byte[] read(
            final InputStream in)
    throws IOException {
        try {
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            int readed = 0;
            byte[] buffer = new byte[2048];
            while ((readed = in.read(buffer)) != -1) {
                bout.write(buffer, 0, readed);
            }

            return bout.toByteArray();
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ex) {
                    LOG.error("could not close stream: {}", ex.getMessage());
                }
            }
        }
    }

    public static void save(
            final String fileName,
            final byte[] encoded)
    throws IOException {
        save(new File(expandFilepath(fileName)), encoded);
    }

    public static void save(
            final File file,
            final byte[] content)
    throws IOException {
        File tmpFile = expandFilepath(file);

        File parent = tmpFile.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }

        FileOutputStream out = new FileOutputStream(tmpFile);
        try {
            out.write(content);
        } finally {
            out.close();
        }
    }

    public static byte[] leftmost(
            final byte[] bytes,
            final int bitCount) {
        int byteLenKey = (bitCount + 7) / 8;

        if (bitCount >= (bytes.length << 3)) {
            return bytes;
        }

        byte[] truncatedBytes = new byte[byteLenKey];
        System.arraycopy(bytes, 0, truncatedBytes, 0, byteLenKey);

        // shift the bits to the right
        if (bitCount % 8 > 0) {
            int shiftBits = 8 - (bitCount % 8);

            for (int i = byteLenKey - 1; i > 0; i--) {
                truncatedBytes[i] = (byte) (
                        (byte2int(truncatedBytes[i]) >>> shiftBits)
                        | ((byte2int(truncatedBytes[i - 1]) << (8 - shiftBits)) & 0xFF));
            }
            truncatedBytes[0] = (byte) (byte2int(truncatedBytes[0]) >>> shiftBits);
        }

        return truncatedBytes;
    }

    private static int byte2int(
            final byte bt) {
        return (bt >= 0)
                ? bt
                : 256 + bt;
    }

    public static String getHostAddress()
    throws SocketException {
        List<String> addresses = new LinkedList<>();

        Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
        while (interfaces.hasMoreElements()) {
            NetworkInterface ni = (NetworkInterface) interfaces.nextElement();
            Enumeration<InetAddress> ee = ni.getInetAddresses();
            while (ee.hasMoreElements()) {
                InetAddress ia = (InetAddress) ee.nextElement();
                if (ia instanceof Inet4Address) {
                    addresses.add(((Inet4Address) ia).getHostAddress());
                }
            }
        }

        for (String addr : addresses) {
            if (!addr.startsWith("192.") && !addr.startsWith("127.")) {
                return addr;
            }
        }

        for (String addr : addresses) {
            if (!addr.startsWith("127.")) {
                return addr;
            }
        }

        if (addresses.size() > 0) {
            return addresses.get(0);
        } else {
            try {
                return InetAddress.getLocalHost().getHostAddress();
            } catch (UnknownHostException ex) {
                return "UNKNOWN";
            }
        }
    }

    public static String expandFilepath(
            final String path) {
        ParamUtil.requireNonBlank("path", path);

        if (path.startsWith("~" + File.separator)) {
            return System.getProperty("user.home") + path.substring(1);
        } else {
            return path;
        }
    }

    public static File expandFilepath(
            final File file) {
        String path = file.getPath();
        String expandedPath = expandFilepath(path);
        if (path.equals(expandedPath)) {
            return file;
        } else {
            return new File(expandedPath);
        }
    }

    public static String convertSequenceName(
            final String sequenceName) {
        StringBuilder sb = new StringBuilder();
        int len = sequenceName.length();
        for (int i = 0; i < len; i++) {
            char ch = sequenceName.charAt(i);
            if ((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')) {
                sb.append(ch);
            } else {
                sb.append("_");
            }
        }
        return sb.toString();
    }

    public static String base64Encode(
            final byte[] data,
            final boolean withLineBreak) {

        String b64Str = Base64.getEncoder().encodeToString(data);
        if (!withLineBreak) {
            return b64Str;
        }

        if (b64Str.length() < 64) {
            return b64Str;
        }

        StringBuilder sb = new StringBuilder();
        final int blockSize = 64;
        final int size = b64Str.length();

        final int nFullBlock = size / blockSize;

        for (int i = 0; i < nFullBlock; i++) {
            int offset = i * blockSize;
            sb.append(b64Str.subSequence(offset, offset + blockSize)).append("\n");
        }

        if (size % blockSize != 0) {
            sb.append(b64Str.substring(nFullBlock * blockSize)).append("\n");
        }
        sb.deleteCharAt(sb.length() - 1);
        return sb.toString();
    }

}
