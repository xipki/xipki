// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.dns;

import org.junit.After;
import org.junit.Assert;
import org.junit.Test;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * JUnit tests of {@link NetDnsTransport} against fake servers on the loopback interface.
 *
 * @author Lijun Liao (xipki)
 */
public class NetDnsTransportTest {

  private interface Responder {
    /** Returns the UDP datagrams to send in response to the query. */
    List<byte[]> respond(byte[] query) throws Exception;
  }

  private static final DnsName QNAME = DnsName.of("_acme-challenge.example.org");

  private final List<AutoCloseable> closeables = new ArrayList<>();

  private final List<byte[]> receivedQueries = Collections.synchronizedList(new ArrayList<>());

  @After
  public void close() throws Exception {
    for (AutoCloseable c : closeables) {
      c.close();
    }
  }

  private InetSocketAddress udpServer(Responder responder) throws IOException {
    DatagramSocket socket = new DatagramSocket(0, InetAddress.getLoopbackAddress());
    closeables.add(socket);
    Thread t = new Thread(() -> {
      byte[] buf = new byte[65535];
      while (!socket.isClosed()) {
        try {
          DatagramPacket packet = new DatagramPacket(buf, buf.length);
          socket.receive(packet);
          byte[] query = Arrays.copyOf(packet.getData(), packet.getLength());
          receivedQueries.add(query);
          for (byte[] resp : responder.respond(query)) {
            socket.send(new DatagramPacket(resp, resp.length, packet.getSocketAddress()));
          }
        } catch (Exception ex) {
          // closed
        }
      }
    });
    t.setDaemon(true);
    t.start();
    return (InetSocketAddress) socket.getLocalSocketAddress();
  }

  private void tcpServer(int port, Responder responder) throws IOException {
    ServerSocket server = new ServerSocket(port, 5, InetAddress.getLoopbackAddress());
    closeables.add(server);
    Thread t = new Thread(() -> {
      while (!server.isClosed()) {
        try (Socket s = server.accept()) {
          DataInputStream in = new DataInputStream(s.getInputStream());
          byte[] query = new byte[in.readUnsignedShort()];
          in.readFully(query);
          OutputStream out = s.getOutputStream();
          byte[] resp = responder.respond(query).get(0);
          out.write(new byte[]{(byte) (resp.length >>> 8), (byte) resp.length});
          out.write(resp);
          out.flush();
        } catch (Exception ex) {
          // closed
        }
      }
    });
    t.setDaemon(true);
    t.start();
  }

  private static NetDnsTransport transport(boolean dnssec, InetSocketAddress... servers) {
    return new NetDnsTransport(Arrays.asList(servers), dnssec, 2000);
  }

  private static byte[] errorResponse(byte[] query, int rcode) throws DnsException {
    DnsMessage q = DnsMessage.parse(query);
    return new TestWire().header(q.id(), DnsMessage.FLAG_QR, rcode, 1, 0, 0, 0)
        .question(q.qname().toString(), q.qtype()).toByteArray();
  }

  private static String firstTxt(DnsMessage m) throws DnsException {
    return m.answer().get(0).txt();
  }

  @Test
  public void simpleQuery() throws Exception {
    InetSocketAddress server = udpServer(q -> Collections.singletonList(
        TestWire.txtResponse(q, 0, "token")));
    DnsMessage m = transport(true, server).query(QNAME, DnsRecord.TYPE_TXT);
    Assert.assertEquals("token", firstTxt(m));

    DnsMessage query = DnsMessage.parse(receivedQueries.get(0));
    Assert.assertTrue("CD", query.flag(DnsMessage.FLAG_CD));
    Assert.assertTrue("RD", query.flag(DnsMessage.FLAG_RD));
  }

  @Test
  public void forgedResponsesIgnored() throws Exception {
    InetSocketAddress server = udpServer(q -> {
      DnsMessage query = DnsMessage.parse(q);
      byte[] wrongId = TestWire.txtResponse(q, 0, "forged");
      wrongId[0] ^= 0x55;
      byte[] wrongQuestion = new TestWire().header(query.id(), DnsMessage.FLAG_QR, 0, 1, 0, 0, 0)
          .question("other.example.org", DnsRecord.TYPE_TXT).toByteArray();
      byte[] notResponse = TestWire.txtResponse(q, 0, "forged");
      notResponse[2] &= 0x7F; // QR = 0
      byte[] garbage = {1, 2, 3};
      return Arrays.asList(wrongId, wrongQuestion, notResponse, garbage,
          TestWire.txtResponse(q, 0, "token"));
    });
    DnsMessage m = transport(false, server).query(QNAME, DnsRecord.TYPE_TXT);
    Assert.assertEquals("token", firstTxt(m));
  }

  @Test
  public void truncatedFallsBackToTcp() throws Exception {
    InetSocketAddress server = udpServer(q -> Collections.singletonList(
        TestWire.txtResponse(q, DnsMessage.FLAG_TC)));
    tcpServer(server.getPort(), q -> Collections.singletonList(
        TestWire.txtResponse(q, 0, "via-tcp")));
    DnsMessage m = transport(true, server).query(QNAME, DnsRecord.TYPE_TXT);
    Assert.assertEquals("via-tcp", firstTxt(m));
  }

  @Test
  public void failoverOnServfail() throws Exception {
    InetSocketAddress bad = udpServer(q -> Collections.singletonList(
        errorResponse(q, DnsMessage.RCODE_SERVFAIL)));
    InetSocketAddress good = udpServer(q -> Collections.singletonList(
        TestWire.txtResponse(q, 0, "token")));
    DnsMessage m = transport(true, bad, good).query(QNAME, DnsRecord.TYPE_TXT);
    Assert.assertEquals("token", firstTxt(m));
  }

  @Test
  public void failoverOnTimeout() throws Exception {
    InetSocketAddress silent = udpServer(q -> Collections.emptyList());
    InetSocketAddress good = udpServer(q -> Collections.singletonList(
        TestWire.txtResponse(q, 0, "token")));
    NetDnsTransport t = new NetDnsTransport(Arrays.asList(silent, good), false, 300);
    Assert.assertEquals("token", firstTxt(t.query(QNAME, DnsRecord.TYPE_TXT)));
  }

  @Test
  public void allServersFail() throws Exception {
    InetSocketAddress silent = udpServer(q -> Collections.emptyList());
    NetDnsTransport t = new NetDnsTransport(Collections.singletonList(silent), false, 300);
    try {
      t.query(QNAME, DnsRecord.TYPE_TXT);
      Assert.fail("expected SocketTimeoutException");
    } catch (SocketTimeoutException ex) {
      // expected
    }

    InetSocketAddress servfail = udpServer(q -> Collections.singletonList(
        errorResponse(q, DnsMessage.RCODE_SERVFAIL)));
    Assert.assertEquals(DnsMessage.RCODE_SERVFAIL,
        transport(false, servfail).query(QNAME, DnsRecord.TYPE_TXT).rcode());
  }

  @Test
  public void formerrRetriedWithoutEdns() throws Exception {
    InetSocketAddress server = udpServer(q -> {
      boolean edns = q[11] != 0; // ARCOUNT: the OPT record
      return Collections.singletonList(edns ? errorResponse(q, DnsMessage.RCODE_FORMERR)
          : TestWire.txtResponse(q, 0, "token"));
    });
    DnsMessage m = transport(false, server).query(QNAME, DnsRecord.TYPE_TXT);
    Assert.assertEquals("token", firstTxt(m));
    Assert.assertEquals(2, receivedQueries.size());

    // with DNSSEC, EDNS is required: no retry
    receivedQueries.clear();
    m = transport(true, server).query(QNAME, DnsRecord.TYPE_TXT);
    Assert.assertEquals(DnsMessage.RCODE_FORMERR, m.rcode());
    Assert.assertEquals(1, receivedQueries.size());
  }

  @Test
  public void parseServers() throws Exception {
    Assert.assertEquals(new InetSocketAddress("192.0.2.1", 53),
        NetDnsTransport.parseServer("192.0.2.1"));
    Assert.assertEquals(new InetSocketAddress("192.0.2.1", 5353),
        NetDnsTransport.parseServer("192.0.2.1:5353"));
    Assert.assertEquals(new InetSocketAddress("2001:db8::1", 53),
        NetDnsTransport.parseServer("2001:db8::1"));
    Assert.assertEquals(new InetSocketAddress("2001:db8::1", 5353),
        NetDnsTransport.parseServer("[2001:db8::1]:5353"));
    Assert.assertEquals(new InetSocketAddress("::1", 53), NetDnsTransport.parseServer("[::1]"));

    for (String invalid : new String[]{"192.0.2.1:0", "192.0.2.1:70000", "192.0.2.1:x",
        "[::1", "[::1]5353"}) {
      try {
        NetDnsTransport.parseServer(invalid);
        Assert.fail("accepted " + invalid);
      } catch (IOException ex) {
        // expected
      }
    }
  }

  @Test
  public void readResolvConf() throws Exception {
    Path file = Files.createTempFile("resolv", ".conf");
    try {
      Files.write(file, ("# comment\nsearch example.org\nnameserver 192.0.2.1\n"
          + "nameserver fe80::1%en0\n  nameserver   2001:db8::53  \noptions ndots:2\n")
          .getBytes(StandardCharsets.UTF_8));
      Assert.assertEquals(Arrays.asList("192.0.2.1", "fe80::1", "2001:db8::53"),
          NetDnsTransport.readResolvConf(file));
    } finally {
      Files.delete(file);
    }
    Assert.assertTrue(NetDnsTransport.readResolvConf(file).isEmpty());
  }

}
