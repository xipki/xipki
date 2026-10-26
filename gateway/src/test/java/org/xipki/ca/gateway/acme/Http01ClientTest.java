// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

/**
 * JUnit test case of {@link Http01Client}.
 * @author Lijun Liao (xipki)
 */
public class Http01ClientTest {

  private static final String PATH = "/.well-known/acme-challenge/token";

  private ServerSocket serverSocket;

  private Thread serverThread;

  private final List<String> requests = Collections.synchronizedList(new ArrayList<>());

  private final AtomicReference<Function<String, String>> handler =
      new AtomicReference<>();

  @Before
  public void startServer() throws IOException {
    serverSocket = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
    serverThread = new Thread(() -> {
      while (!serverSocket.isClosed()) {
        try (Socket socket = serverSocket.accept()) {
          String request = readRequest(socket.getInputStream());
          requests.add(request);
          OutputStream out = socket.getOutputStream();
          out.write(handler.get().apply(request).getBytes(StandardCharsets.ISO_8859_1));
          out.flush();
        } catch (IOException ex) {
          // server closed
        }
      }
    });
    serverThread.setDaemon(true);
    serverThread.start();
  }

  @After
  public void stopServer() throws Exception {
    serverSocket.close();
    serverThread.join(5000);
  }

  private Http01Client client() {
    int port = serverSocket.getLocalPort();
    return new Http01Client(host -> {
      if (host.equals("forbidden.test")) {
        throw new UnknownHostException("host resolves to forbidden address");
      }
      return new InetAddress[]{InetAddress.getLoopbackAddress()};
    }, null, port, port);
  }

  @Test
  public void contentLength() throws IOException {
    handler.set(req -> "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabcde");
    byte[] body = client().get("example.com", PATH);
    Assert.assertEquals("abcde", new String(body, StandardCharsets.UTF_8));

    String request = requests.get(0);
    Assert.assertTrue(request, request.startsWith("GET " + PATH + " HTTP/1.1\r\n"));
    Assert.assertTrue(request, request.contains("\r\nHost: example.com\r\n"));
  }

  @Test
  public void chunked() throws IOException {
    handler.set(req -> "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        + "3\r\nabc\r\n2;ext=1\r\nde\r\n0\r\n\r\n");
    Assert.assertEquals("abcde", new String(client().get("example.com", PATH),
        StandardCharsets.UTF_8));
  }

  @Test
  public void readUntilClose() throws IOException {
    handler.set(req -> "HTTP/1.0 200 OK\r\n\r\nabcde");
    Assert.assertEquals("abcde", new String(client().get("example.com", PATH),
        StandardCharsets.UTF_8));
  }

  @Test
  public void non200IsRejected() {
    handler.set(req -> "HTTP/1.1 404 Not Found\r\nContent-Length: 5\r\n\r\nabcde");
    Assert.assertThrows(IOException.class, () -> client().get("example.com", PATH));
  }

  @Test
  public void bodyTooLarge() {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < 5000; i++) {
      sb.append('a');
    }
    String body = sb.toString();

    handler.set(req -> "HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n" + body);
    Assert.assertThrows(IOException.class, () -> client().get("example.com", PATH));

    handler.set(req -> "HTTP/1.0 200 OK\r\n\r\n" + body);
    Assert.assertThrows(IOException.class, () -> client().get("example.com", PATH));
  }

  @Test
  public void redirectIsFollowed() throws IOException {
    int port = serverSocket.getLocalPort();
    handler.set(req -> req.startsWith("GET " + PATH + " ")
        ? "HTTP/1.1 302 Found\r\nLocation: http://other.example.com:" + port
            + "/new?a=b\r\nContent-Length: 0\r\n\r\n"
        : "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabcde");

    Assert.assertEquals("abcde", new String(client().get("example.com", PATH),
        StandardCharsets.UTF_8));
    Assert.assertEquals(2, requests.size());
    String request = requests.get(1);
    Assert.assertTrue(request, request.startsWith("GET /new?a=b HTTP/1.1\r\n"));
    Assert.assertTrue(request, request.contains("\r\nHost: other.example.com\r\n"));
  }

  @Test
  public void redirectToForbiddenHostIsRejected() {
    int port = serverSocket.getLocalPort();
    handler.set(req -> "HTTP/1.1 302 Found\r\nLocation: http://forbidden.test:" + port
        + "/\r\nContent-Length: 0\r\n\r\n");
    Assert.assertThrows(UnknownHostException.class, () -> client().get("example.com", PATH));
    Assert.assertEquals(1, requests.size());
  }

  @Test
  public void redirectToOtherPortIsRejected() {
    handler.set(req -> "HTTP/1.1 302 Found\r\nLocation: http://example.com:8080/\r\n"
        + "Content-Length: 0\r\n\r\n");
    Assert.assertThrows(IOException.class, () -> client().get("example.com", PATH));
  }

  @Test
  public void redirectToHttpsWithoutSslIsRejected() {
    int port = serverSocket.getLocalPort();
    handler.set(req -> "HTTP/1.1 302 Found\r\nLocation: https://example.com:" + port
        + "/\r\nContent-Length: 0\r\n\r\n");
    Assert.assertThrows(IOException.class, () -> client().get("example.com", PATH));
  }

  @Test
  public void tooManyRedirects() {
    handler.set(req -> "HTTP/1.1 302 Found\r\nLocation: " + PATH + "\r\nContent-Length: 0\r\n\r\n");
    Assert.assertThrows(IOException.class, () -> client().get("example.com", PATH));
    // initial request + 5 redirects
    Assert.assertEquals(6, requests.size());
  }

  private static String readRequest(InputStream in) throws IOException {
    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    int b;
    while ((b = in.read()) != -1) {
      bout.write(b);
      byte[] bytes = bout.toByteArray();
      int n = bytes.length;
      if (n >= 4 && bytes[n - 4] == '\r' && bytes[n - 3] == '\n'
          && bytes[n - 2] == '\r' && bytes[n - 1] == '\n') {
        break;
      }
    }
    return new String(bout.toByteArray(), StandardCharsets.ISO_8859_1);
  }

}
