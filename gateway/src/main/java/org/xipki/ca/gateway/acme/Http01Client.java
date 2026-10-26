// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.xipki.codec.util.Args;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Minimal HTTP client to fetch the HTTP-01 challenge response.
 * <p>
 * Each host (including redirect targets) is resolved exactly once via the
 * {@link HostResolver}, and the connection is made to the resolved address,
 * so that the address check cannot be bypassed by DNS rebinding or redirects.
 * Only status 200 is accepted, and the sizes of header and body are limited.
 *
 * @author Lijun Liao (xipki)
 */
class Http01Client {

  interface HostResolver {
    /**
     * Resolves the host. Throws exception if the host or any of its addresses
     * is not allowed.
     */
    InetAddress[] resolve(String host) throws IOException;
  }

  static final int CONNECT_TIMEOUT_MS = 10_000;

  private static final int TOTAL_TIMEOUT_MS = 30_000;

  private static final int MAX_REDIRECTS = 5;

  private static final int MAX_HEADER_SIZE = 8 * 1024;

  private static final int MAX_BODY_SIZE = 4 * 1024;

  private final HostResolver resolver;

  private final SSLSocketFactory sslSocketFactory;

  private final int httpPort;

  private final int httpsPort;

  Http01Client(HostResolver resolver, SSLSocketFactory sslSocketFactory) {
    this(resolver, sslSocketFactory, 80, 443);
  }

  // for test
  Http01Client(HostResolver resolver, SSLSocketFactory sslSocketFactory,
               int httpPort, int httpsPort) {
    this.resolver = Args.notNull(resolver, "resolver");
    this.sslSocketFactory = sslSocketFactory;
    this.httpPort = httpPort;
    this.httpsPort = httpsPort;
  }

  byte[] get(String host, String path) throws IOException {
    long deadline = System.currentTimeMillis() + TOTAL_TIMEOUT_MS;

    boolean https = false;
    int port = httpPort;
    URI uri = toUri("http", host, port, path);

    for (int redirects = 0; ; redirects++) {
      InetAddress[] addresses = resolver.resolve(host);
      try (Socket socket = open(addresses, host, port, https, deadline)) {
        OutputStream out = socket.getOutputStream();
        String request = "GET " + path + " HTTP/1.1\r\n"
            + "Host: " + host + "\r\n"
            + "User-Agent: xipki-acme\r\n"
            + "Accept: */*\r\n"
            + "Connection: close\r\n\r\n";
        out.write(request.getBytes(StandardCharsets.US_ASCII));
        out.flush();

        InputStream in = new DeadlineInputStream(socket, deadline);
        int[] headerSize = {0};
        String statusLine = readLine(in, headerSize);
        int status = parseStatus(statusLine);
        Map<String, String> headers = readHeaders(in, headerSize);

        if (isRedirect(status)) {
          if (redirects >= MAX_REDIRECTS) {
            throw new IOException("too many redirects");
          }

          String location = headers.get("location");
          if (location == null) {
            throw new IOException("redirect without Location header");
          }

          URI next;
          try {
            next = uri.resolve(new URI(location.trim()));
          } catch (URISyntaxException | IllegalArgumentException ex) {
            throw new IOException("invalid Location header '" + location + "'");
          }

          String scheme = next.getScheme() == null ? "" : next.getScheme().toLowerCase(Locale.ROOT);
          if ("http".equals(scheme)) {
            https = false;
          } else if ("https".equals(scheme)) {
            if (sslSocketFactory == null) {
              throw new IOException("redirect to https is not supported");
            }
            https = true;
          } else {
            throw new IOException("redirect to unsupported scheme '" + scheme + "'");
          }

          int allowedPort = https ? httpsPort : httpPort;
          int nextPort = next.getPort() == -1 ? (https ? 443 : 80) : next.getPort();
          if (nextPort != allowedPort) {
            throw new IOException("redirect to forbidden port " + nextPort);
          }

          host = next.getHost();
          if (host == null || host.isEmpty()) {
            throw new IOException("redirect without host");
          }

          port = nextPort;
          path = next.getRawPath() == null || next.getRawPath().isEmpty() ? "/" : next.getRawPath();
          if (next.getRawQuery() != null) {
            path += "?" + next.getRawQuery();
          }
          uri = next;
          continue;
        }

        if (status != 200) {
          throw new IOException("received HTTP status " + status);
        }

        String transferEncoding = headers.get("transfer-encoding");
        if (transferEncoding != null
            && transferEncoding.toLowerCase(Locale.ROOT).contains("chunked")) {
          return readChunkedBody(in);
        }

        String contentLength = headers.get("content-length");
        if (contentLength != null) {
          long len;
          try {
            len = Long.parseLong(contentLength.trim());
          } catch (NumberFormatException ex) {
            throw new IOException("invalid Content-Length '" + contentLength + "'");
          }

          if (len < 0 || len > MAX_BODY_SIZE) {
            throw new IOException("Content-Length " + len + " not in [0, " + MAX_BODY_SIZE + "]");
          }
          return readFully(in, (int) len);
        }

        return readToEnd(in);
      }
    }
  }

  static Socket connect(InetAddress[] addresses, int port, int timeoutMs) throws IOException {
    IOException lastEx = null;
    for (InetAddress address : addresses) {
      Socket socket = new Socket();
      try {
        socket.connect(new InetSocketAddress(address, port), timeoutMs);
        return socket;
      } catch (IOException ex) {
        lastEx = ex;
        socket.close();
      }
    }

    throw (lastEx != null) ? lastEx : new IOException("no address to connect");
  }

  private Socket open(InetAddress[] addresses, String host, int port,
                      boolean https, long deadline) throws IOException {
    int timeout = (int) Math.min(CONNECT_TIMEOUT_MS, remaining(deadline));
    Socket socket = connect(addresses, port, timeout);
    if (!https) {
      return socket;
    }

    try {
      SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(socket, host, port, true);
      sslSocket.setSoTimeout((int) remaining(deadline));
      sslSocket.startHandshake();
      return sslSocket;
    } catch (IOException | RuntimeException ex) {
      socket.close();
      throw ex;
    }
  }

  private static URI toUri(String scheme, String host, int port, String path) throws IOException {
    try {
      return new URI(scheme, null, host, port, path, null, null);
    } catch (URISyntaxException ex) {
      throw new IOException("invalid URL", ex);
    }
  }

  private static boolean isRedirect(int status) {
    return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
  }

  private static int parseStatus(String statusLine) throws IOException {
    // HTTP/1.1 200 OK
    String[] tokens = statusLine.split(" ", 3);
    if (tokens.length < 2 || !tokens[0].startsWith("HTTP/")) {
      throw new IOException("invalid HTTP status line");
    }

    try {
      return Integer.parseInt(tokens[1]);
    } catch (NumberFormatException ex) {
      throw new IOException("invalid HTTP status line");
    }
  }

  private static Map<String, String> readHeaders(InputStream in, int[] headerSize)
      throws IOException {
    Map<String, String> headers = new HashMap<>();
    while (true) {
      String line = readLine(in, headerSize);
      if (line.isEmpty()) {
        return headers;
      }

      int idx = line.indexOf(':');
      if (idx <= 0) {
        throw new IOException("invalid HTTP header line");
      }

      String name = line.substring(0, idx).trim().toLowerCase(Locale.ROOT);
      String value = line.substring(idx + 1).trim();
      if (headers.containsKey(name)
          && ("content-length".equals(name) || "transfer-encoding".equals(name)
              || "location".equals(name))) {
        throw new IOException("duplicated HTTP header " + name);
      }
      headers.put(name, value);
    }
  }

  /**
   * Reads a line terminated by LF (optionally preceded by CR), without the terminator.
   */
  private static String readLine(InputStream in, int[] size) throws IOException {
    ByteArrayOutputStream line = new ByteArrayOutputStream();
    while (true) {
      int b = in.read();
      if (b == -1) {
        throw new IOException("unexpected end of HTTP response");
      }

      if (++size[0] > MAX_HEADER_SIZE) {
        throw new IOException("HTTP header too large");
      }

      if (b == '\n') {
        break;
      }
      line.write(b);
    }

    byte[] bytes = line.toByteArray();
    int len = bytes.length;
    if (len > 0 && bytes[len - 1] == '\r') {
      len--;
    }
    return new String(bytes, 0, len, StandardCharsets.ISO_8859_1);
  }

  private static byte[] readChunkedBody(InputStream in) throws IOException {
    ByteArrayOutputStream body = new ByteArrayOutputStream();
    int[] lineSize = {0};
    while (true) {
      String sizeLine = readLine(in, lineSize);
      int idx = sizeLine.indexOf(';');
      if (idx != -1) {
        sizeLine = sizeLine.substring(0, idx);
      }

      int chunkSize;
      try {
        chunkSize = Integer.parseInt(sizeLine.trim(), 16);
      } catch (NumberFormatException ex) {
        throw new IOException("invalid chunk size");
      }

      if (chunkSize < 0 || body.size() + chunkSize > MAX_BODY_SIZE) {
        throw new IOException("HTTP body too large");
      }

      if (chunkSize == 0) {
        // ignore the trailers
        return body.toByteArray();
      }

      body.write(readFully(in, chunkSize));
      // CRLF after the chunk data
      if (!readLine(in, lineSize).isEmpty()) {
        throw new IOException("invalid chunk terminator");
      }
    }
  }

  private static byte[] readFully(InputStream in, int len) throws IOException {
    byte[] bytes = new byte[len];
    int off = 0;
    while (off < len) {
      int n = in.read(bytes, off, len - off);
      if (n == -1) {
        throw new IOException("unexpected end of HTTP response");
      }
      off += n;
    }
    return bytes;
  }

  private static byte[] readToEnd(InputStream in) throws IOException {
    ByteArrayOutputStream body = new ByteArrayOutputStream();
    byte[] buffer = new byte[1024];
    int n;
    while ((n = in.read(buffer)) != -1) {
      if (body.size() + n > MAX_BODY_SIZE) {
        throw new IOException("HTTP body too large");
      }
      body.write(buffer, 0, n);
    }
    return body.toByteArray();
  }

  private static long remaining(long deadline) throws IOException {
    long remaining = deadline - System.currentTimeMillis();
    if (remaining <= 0) {
      throw new IOException("timeout while fetching HTTP-01 challenge response");
    }
    return remaining;
  }

  /**
   * Limits the total time used to read the response.
   */
  private static class DeadlineInputStream extends InputStream {

    private final Socket socket;

    private final InputStream in;

    private final long deadline;

    DeadlineInputStream(Socket socket, long deadline) throws IOException {
      this.socket = socket;
      this.in = socket.getInputStream();
      this.deadline = deadline;
    }

    @Override
    public int read() throws IOException {
      socket.setSoTimeout((int) remaining(deadline));
      return in.read();
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
      socket.setSoTimeout((int) remaining(deadline));
      return in.read(b, off, len);
    }

  }

}
