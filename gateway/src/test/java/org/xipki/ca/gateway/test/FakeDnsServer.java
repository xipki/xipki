// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * A minimal DNS server over UDP on the loopback address, for the dns-01 challenges of ACME. It
 * answers TXT queries with the records set by {@link #setTxt(String, String)}, and all other
 * queries with an empty NOERROR response.
 *
 * @author Lijun Liao (xipki)
 */
final class FakeDnsServer implements AutoCloseable {

  private static final int TYPE_TXT = 16;

  private final DatagramSocket socket;

  private final Map<String, List<String>> txtRecords = new ConcurrentHashMap<>();

  private final Thread thread;

  private volatile boolean stop;

  FakeDnsServer() throws SocketException {
    socket = new DatagramSocket(0, InetAddress.getLoopbackAddress());
    thread = new Thread(this::serve, "fake-dns");
    thread.setDaemon(true);
    thread.start();
  }

  /** The address of this server in the form {@code 127.0.0.1:port}. */
  String address() {
    return "127.0.0.1:" + socket.getLocalPort();
  }

  /** Adds a TXT record. */
  void setTxt(String name, String value) {
    txtRecords.computeIfAbsent(normalize(name), k -> new CopyOnWriteArrayList<>()).add(value);
  }

  @Override
  public void close() {
    stop = true;
    socket.close();
  }

  private void serve() {
    byte[] buf = new byte[1500];
    while (!stop) {
      DatagramPacket packet = new DatagramPacket(buf, buf.length);
      try {
        socket.receive(packet);
        byte[] response = respond(buf, packet.getLength());
        if (response != null) {
          socket.send(new DatagramPacket(response, response.length, packet.getSocketAddress()));
        }
      } catch (IOException | RuntimeException ex) {
        if (stop) {
          return;
        }
      }
    }
  }

  /**
   * Builds the response for a query with exactly one question. The question is copied, and the
   * additional records of the query (e.g. EDNS OPT) are ignored.
   */
  private byte[] respond(byte[] query, int len) {
    if (len < 12 || ((query[4] & 0xFF) << 8 | (query[5] & 0xFF)) != 1) {
      return null;
    }

    // parse QNAME
    StringBuilder name = new StringBuilder();
    int off = 12;
    while (true) {
      int labelLen = query[off++] & 0xFF;
      if (labelLen == 0) {
        break;
      }
      if (name.length() > 0) {
        name.append('.');
      }
      name.append(new String(query, off, labelLen, StandardCharsets.US_ASCII));
      off += labelLen;
    }
    int qtype = (query[off] & 0xFF) << 8 | (query[off + 1] & 0xFF);
    int questionEnd = off + 4; // QTYPE and QCLASS

    List<String> values = (qtype == TYPE_TXT) ? txtRecords.get(normalize(name.toString())) : null;
    int numAnswers = values == null ? 0 : values.size();

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    // header: ID, flags (QR, RD, RA; NOERROR), QDCOUNT=1, ANCOUNT, NSCOUNT=0, ARCOUNT=0
    out.write(query[0]);
    out.write(query[1]);
    out.write(0x81);
    out.write(0x80);
    writeShort(out, 1);
    writeShort(out, numAnswers);
    writeShort(out, 0);
    writeShort(out, 0);
    out.write(query, 12, questionEnd - 12);

    for (int i = 0; i < numAnswers; i++) {
      byte[] text = values.get(i).getBytes(StandardCharsets.US_ASCII);
      // NAME: pointer to the QNAME at offset 12
      out.write(0xC0);
      out.write(12);
      writeShort(out, TYPE_TXT);
      writeShort(out, 1); // class IN
      writeShort(out, 0); // TTL (high)
      writeShort(out, 60); // TTL (low)
      writeShort(out, text.length + 1);
      out.write(text.length);
      out.write(text, 0, text.length);
    }
    return out.toByteArray();
  }

  private static void writeShort(ByteArrayOutputStream out, int value) {
    out.write((value >> 8) & 0xFF);
    out.write(value & 0xFF);
  }

  private static String normalize(String name) {
    String ret = name.toLowerCase(Locale.ROOT);
    return ret.endsWith(".") ? ret.substring(0, ret.length() - 1) : ret;
  }

}
