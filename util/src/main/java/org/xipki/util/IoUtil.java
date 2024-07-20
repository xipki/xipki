// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URL;
import java.net.URLConnection;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;

/**
 * IO utility class.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class IoUtil {

  static final String USER_HOME = System.getProperty("user.home");

  private static final Logger LOG = LoggerFactory.getLogger(IoUtil.class);

  private IoUtil() {
  }

  public static void closeQuietly(Closeable closable) {
    if (closable == null) {
      return;
    }
    try {
      closable.close();
    } catch (Throwable th) {
      LOG.error("could not close closable: {}", th.getMessage());
    }
  }

  public static byte[] read(String fileName) throws IOException {
    return read(fileName, false);
  }

  public static byte[] read(String fileName, boolean prependBaseDir) throws IOException {
    return Files.readAllBytes(Paths.get(expandFilepath(fileName, prependBaseDir)));
  }

  public static byte[] read(File file) throws IOException {
    return read(file, false);
  }

  public static byte[] read(File file, boolean prependBaseDir) throws IOException {
    return Files.readAllBytes(Paths.get(expandFilepath(file.getPath(), prependBaseDir)));
  }

  /**
   * Read all bytes from the input stream and close the stream.
   * The specified stream is closed after this method returns.
   * @param in the input stream.
   * @return the byte array contained in the input stream.
   * @throws IOException if error occurs while reading the bytes.
   */
  public static byte[] readAllBytesAndClose(InputStream in) throws IOException {
    try {
      return readAllBytes(in);
    } finally {
      try {
        in.close();
      } catch (IOException ex) {
        LOG.error("could not close stream: {}", ex.getMessage());
      }
    }
  }

  /**
   * Read all bytes from the input stream.
   * The specified stream remains open after this method returns.
   * @param in the input stream.
   * @return the byte array contained in the input stream.
   * @throws IOException if error occurs while reading the bytes.
   */
  public static byte[] readAllBytes(InputStream in) throws IOException {
    try (ByteArrayOutputStream bout = new ByteArrayOutputStream()) {
      int read;
      byte[] buffer = new byte[2048];
      while ((read = in.read(buffer)) != -1) {
        bout.write(buffer, 0, read);
      }

      return bout.toByteArray();
    }
  }

  public static void save(String fileName, byte[] encoded) throws IOException {
    save(fileName, encoded, false);
  }

  public static void save(String fileName, byte[] encoded, boolean prependBaseDir) throws IOException {
    save(new File(fileName), encoded, prependBaseDir);
  }

  public static void save(File file, byte[] content) throws IOException {
    save(file, content, false);
  }

  public static void save(File file, byte[] content, boolean prependBaseDir) throws IOException {
    File tmpFile = expandFilepath(file, prependBaseDir);
    mkdirsParent(tmpFile.toPath());

    try (InputStream is = new ByteArrayInputStream(content)) {
      Files.copy(is, tmpFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
    }
  }

  public static void mkdirsParent(Path path) throws IOException {
    Path parent = path.getParent();
    if (parent != null) {
      Files.createDirectories(parent);
    }
  }

  public static void mkdirs(File dir) throws IOException {
    if (dir.exists()) {
      if (!dir.isDirectory()) {
        throw new IOException("Path " + dir.getPath() + " exists but is not a directory");
      }
    } else {
      if (!dir.mkdirs()) {
        throw new IOException("Could not mkdirs for " + dir.getPath());
      }
    }
  }

  public static void renameTo(File srcFile, File destFile) throws IOException {
    if (!srcFile.renameTo(destFile)) {
      throw new IOException("Could not rename " + srcFile.getPath() + " to " + destFile.getPath());
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

    if (!addresses.isEmpty()) {
      return addresses.get(0);
    } else {
      try {
        return InetAddress.getLocalHost().getHostAddress();
      } catch (UnknownHostException ex) {
        return "UNKNOWN";
      }
    }
  }

  public static boolean deleteFile(String path) {
    return deleteFile(new File(path), false);
  }

  public static boolean deleteFile(String path, boolean prependBaseDir) {
    return deleteFile(new File(path), prependBaseDir);
  }

  public static boolean deleteFile(File file) {
    return deleteFile(file, false);
  }

  public static void deleteFile0(File file) throws IOException {
    if (!deleteFile(file)) {
      throw new IOException("Could not delete " + file.getPath());
    }
  }

  public static boolean deleteFile(File file, boolean prependBaseDir) {
    file = expandFilepath(file, prependBaseDir);
    if (file.exists()) {
      return file.delete();
    }
    return true;
  }

  public static boolean deleteDir(File dir) {
    return deleteDir(dir, false);
  }

  public static boolean deleteDir(File dir, boolean prependBaseDir) {
    dir = expandFilepath(dir, prependBaseDir);
    try {
      FileUtils.deleteDirectory(dir);
      return true;
    } catch (IOException e) {
      LogUtil.error(LOG, e);
      return false;
    }
  }

  public static String expandFilepath(String path) {
    return expandFilepath(path, false);
  }

  public static String expandFilepath(String path, boolean prependBaseDir) {
    if (Args.notBlank(path, "path").startsWith("~")) {
      return USER_HOME + path.substring(1);
    }

    if (path.startsWith("/")) {
      // unix
      return path;
    }

    int index = path.indexOf(':');
    if (index == 1 || index == 2) {
      // windows
      return path;
    }

    if (prependBaseDir) {
      return XipkiBaseDir.basedir() == null ? path : Paths.get(XipkiBaseDir.basedir(), path).toString();
    } else {
      return path;
    }
  }

  public static File expandFilepath(File file) {
    return expandFilepath(file, false);
  }

  public static File expandFilepath(File file, boolean prependBaseDir) {
    String path = file.getPath();
    String expandedPath = expandFilepath(path, prependBaseDir);
    return path.equals(expandedPath) ? file : new File(expandedPath);
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
    return (0xFF & bytes[offset++]) << 24 | (0xFF & bytes[offset++]) << 16
          | (0xFF & bytes[offset++]) << 8 |  0xFF & bytes[offset];
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
    return Base64.encodeToString(data, withLineBreak);
  }

  public static HttpURLConnection openHttpConn(URL url) throws IOException {
    URLConnection conn = Args.notNull(url, "url").openConnection();
    if (conn instanceof HttpURLConnection) {
      return (HttpURLConnection) conn;
    }
    throw new IOException(url + " is not of protocol HTTP: " + url.getProtocol());
  }

  public static char[] readPasswordFromConsole(String prompt) {
    Console console = System.console();
    if (console == null) {
      throw new IllegalStateException("No console is available for input");
    }
    System.out.println(prompt == null ? "Enter the password" : prompt);
    return console.readPassword();
  }

  public static String readLineFromConsole(String prompt) {
    Console console = System.console();
    if (console == null) {
      throw new IllegalStateException("No console is available for input");
    }
    if (prompt != null) {
      System.out.print(prompt);
    }
    return console.readLine();
  }

  public static ConfigurableProperties loadProperties(String path) throws IOException {
    return loadProperties(path, false);
  }

  public static ConfigurableProperties loadProperties(String path, boolean prependBaseDir) throws IOException {
    Path realPath = Paths.get(expandFilepath(path, prependBaseDir));
    if (!Files.exists(realPath)) {
      throw new IOException("File " + path + " does not exist");
    }

    if (!Files.isReadable(realPath)) {
      throw new IOException("File " + path + " is not readable");
    }

    ConfigurableProperties props = new ConfigurableProperties();
    try (InputStream is = Files.newInputStream(realPath)) {
      props.load(is);
    }
    return props;
  }

  public static String detectPath(String path) {
    File file = new File(path);
    file = expandFilepath(file, false);
    if (!file.exists()) {
      File file2 = expandFilepath(file, true);
      if (file2.exists()) {
        file = file2;
      }
    }

    try {
      return file.getCanonicalPath();
    } catch (IOException ex) {
      return path;
    }
  }

  // Read last line of the file
  public static String readLastNonBlankLine(File file) throws IOException  {
    StringBuilder builder = new StringBuilder();
    try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
      long fileLength = file.length() - 1;
      if (fileLength < 1) {
        return "";
      }

      // Set the pointer at the last of the file
      raf.seek(fileLength);
      long pointer = fileLength;

      while (true) {
        while (pointer >= 0) {
          raf.seek(pointer--);

          char c;
          // read from the last one char at the time
          c = (char) raf.read();
          // break when end of the line
          if (c == '\n') {
            break;
          }
          builder.append(c);
        }

        if (builder.length() > 0) {
          break;
        }
      }

      // Since line is read from the last, so it
      // is in reverse so use reverse method to make it right
      builder.reverse();

      return builder.toString();
    }
  }

}
