/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.common.util;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URL;
import java.net.URLConnection;
import java.net.UnknownHostException;
import java.util.Base64;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class IoUtil {
  private static final Logger LOG = LoggerFactory.getLogger(IoUtil.class);

  private IoUtil() {
  }

  public static void closeStream(OutputStream stream) {
    if (stream == null) {
      return;
    }
    try {
      stream.close();
    } catch (Throwable th) {
      LOG.error("could not close stream: {}", th.getMessage());
    }
  }

  public static byte[] read(String fileName) throws IOException {
    return read(new File(expandFilepath(fileName)));
  }

  public static byte[] read(File file) throws IOException {
    return read(new FileInputStream(expandFilepath(file)));
  }

  public static byte[] read(InputStream in) throws IOException {
    try {
      ByteArrayOutputStream bout = new ByteArrayOutputStream();
      int readed = 0;
      byte[] buffer = new byte[2048];
      while ((readed = in.read(buffer)) != -1) {
        bout.write(buffer, 0, readed);
      }

      return bout.toByteArray();
    } finally {
      try {
        in.close();
      } catch (IOException ex) {
        LOG.error("could not close stream: {}", ex.getMessage());
      }
    }
  }

  public static void save(String fileName, byte[] encoded) throws IOException {
    save(new File(expandFilepath(fileName)), encoded);
  }

  public static void save(File file, byte[] content) throws IOException {
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

  public static String getHostAddress() throws SocketException {
    List<String> addresses = new LinkedList<>();

    Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
    while (interfaces.hasMoreElements()) {
      NetworkInterface ni = interfaces.nextElement();
      Enumeration<InetAddress> ee = ni.getInetAddresses();
      while (ee.hasMoreElements()) {
        InetAddress ia = ee.nextElement();
        if (ia instanceof Inet4Address) {
          addresses.add(ia.getHostAddress());
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

  public static String expandFilepath(String path) {
    ParamUtil.requireNonBlank("path", path);

    return path.startsWith("~" + File.separator)
        ? System.getProperty("user.home") + path.substring(1) : path;
  }

  public static File expandFilepath(File file) {
    String path = file.getPath();
    String expandedPath = expandFilepath(path);
    if (path.equals(expandedPath)) {
      return file;
    } else {
      return new File(expandedPath);
    }
  }

  public static String convertSequenceName(String sequenceName) {
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

  public static void writeShort(short value, byte[] dest, int destOffset) {
    dest[destOffset++] = (byte) (value >> 8);
    dest[destOffset] = (byte) (0xFF & value);
  }

  public static short parseShort(byte[] bytes, int offset) {
    return (short) ((0xFF & bytes[offset++]) << 8 | 0xFF & bytes[offset]);
  }

  public static void writeInt(int value, byte[] dest, int destOffset) {
    dest[destOffset++] = (byte)         (value >> 24);
    dest[destOffset++] = (byte) (0xFF & (value >> 16));
    dest[destOffset++] = (byte) (0xFF & (value >> 8));
    dest[destOffset]   = (byte) (0xFF &  value);
  }

  public static int parseInt(byte[] bytes, int offset) {
    return (0xFF & bytes[offset++]) << 24
        | (0xFF & bytes[offset++]) << 16
        | (0xFF & bytes[offset++]) << 8
        |  0xFF & bytes[offset];
  }

  public static int getIndex(byte[] arrayA, byte[] arrayB) {
    int endIndex = arrayA.length - arrayB.length;
    for (int i = 0; i < endIndex; i++) {
      boolean found = true;
      for (int j = 0; j < arrayB.length; j++) {
        if (arrayA[i + j] != arrayB[j]) {
          found = false;
          break;
        }
      }
      if (found) {
        return i;
      }
    }
    return -1;
  }

  public static String base64Encode(byte[] data, boolean withLineBreak) {

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

  public static HttpURLConnection openHttpConn(URL url) throws IOException {
    ParamUtil.requireNonNull("url", url);
    URLConnection conn = url.openConnection();
    if (conn instanceof HttpURLConnection) {
      return (HttpURLConnection) conn;
    }
    throw new IOException(url.toString() + " is not of protocol HTTP: " + url.getProtocol());
  }
}
