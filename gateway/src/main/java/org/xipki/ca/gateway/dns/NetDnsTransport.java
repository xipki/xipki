// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.dns;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Stub resolver transport over UDP, with fallback to TCP for truncated responses.
 * <p>
 * Each query uses a random ID and a new socket with an ephemeral source port. Responses
 * whose ID, source or question do not match are ignored, so that a single forged
 * packet does not make the query fail. The servers are tried in order; the next one
 * is used after a timeout, an I/O error, SERVFAIL or REFUSED.
 *
 * @author Lijun Liao (xipki)
 */
public class NetDnsTransport implements DnsTransport {

  private static final Logger LOG = LoggerFactory.getLogger(NetDnsTransport.class);

  public static final int DEFAULT_TIMEOUT_MS = 5_000;

  private static final int DEFAULT_PORT = 53;

  private static final int MAX_MESSAGE_SIZE = 65535;

  private static final SecureRandom RANDOM = new SecureRandom();

  private final List<InetSocketAddress> servers;

  private final boolean dnssec;

  private final int timeoutMs;

  /**
   * Constructor.
   *
   * @param servers the recursive resolvers.
   * @param dnssec whether to request DNSSEC records (DO=1, CD=1).
   * @param timeoutMs timeout per server in milliseconds.
   */
  public NetDnsTransport(List<InetSocketAddress> servers, boolean dnssec, int timeoutMs) {
    if (servers == null || servers.isEmpty()) {
      throw new IllegalArgumentException("servers must not be empty");
    }
    if (timeoutMs <= 0) {
      throw new IllegalArgumentException("timeoutMs must be positive");
    }
    this.servers = Collections.unmodifiableList(new ArrayList<>(servers));
    this.dnssec = dnssec;
    this.timeoutMs = timeoutMs;
  }

  /**
   * Parses the server specifications: {@code 192.0.2.1}, {@code 192.0.2.1:5353},
   * {@code 2001:db8::1}, {@code [2001:db8::1]:5353} or a host name (resolved now).
   * If {@code specs} is empty, the name servers of {@code /etc/resolv.conf} are used.
   *
   * @param specs the server specifications, may be {@code null}.
   * @return the server addresses.
   * @throws IOException if a server cannot be parsed or resolved, or no server is found.
   */
  public static List<InetSocketAddress> parseServers(List<String> specs) throws IOException {
    List<String> list = specs;
    if (list == null || list.isEmpty()) {
      list = readResolvConf(Paths.get("/etc/resolv.conf"));
      if (list.isEmpty()) {
        throw new IOException("no DNS servers configured and none found in /etc/resolv.conf");
      }
    }

    List<InetSocketAddress> ret = new ArrayList<>(list.size());
    for (String spec : list) {
      ret.add(parseServer(spec.trim()));
    }
    return ret;
  }

  static InetSocketAddress parseServer(String spec) throws IOException {
    String host = spec;
    int port = DEFAULT_PORT;
    if (spec.startsWith("[")) {
      int idx = spec.indexOf(']');
      if (idx == -1) {
        throw new IOException("invalid DNS server '" + spec + "'");
      }
      host = spec.substring(1, idx);
      String rest = spec.substring(idx + 1);
      if (!rest.isEmpty()) {
        if (!rest.startsWith(":")) {
          throw new IOException("invalid DNS server '" + spec + "'");
        }
        port = parsePort(spec, rest.substring(1));
      }
    } else if (spec.indexOf(':') == spec.lastIndexOf(':') && spec.indexOf(':') != -1) {
      // exactly one colon: host:port
      int idx = spec.indexOf(':');
      host = spec.substring(0, idx);
      port = parsePort(spec, spec.substring(idx + 1));
    }

    InetAddress addr = InetAddress.getByName(host);
    return new InetSocketAddress(addr, port);
  }

  private static int parsePort(String spec, String str) throws IOException {
    try {
      int port = Integer.parseInt(str);
      if (port > 0 && port < 65536) {
        return port;
      }
    } catch (NumberFormatException ex) {
      // handled below
    }
    throw new IOException("invalid port in DNS server '" + spec + "'");
  }

  static List<String> readResolvConf(Path path) {
    List<String> ret = new ArrayList<>(3);
    if (!Files.isReadable(path)) {
      return ret;
    }

    try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
      String line;
      while ((line = reader.readLine()) != null) {
        String[] tokens = line.trim().split("\\s+");
        if (tokens.length >= 2 && tokens[0].equals("nameserver")) {
          String server = tokens[1];
          // strip the IPv6 zone index, e.g. fe80::1%eth0
          int idx = server.indexOf('%');
          ret.add(idx == -1 ? server : server.substring(0, idx));
        }
      }
    } catch (IOException ex) {
      LOG.warn("could not read {}: {}", path, ex.getMessage());
    }
    return ret;
  }

  @Override
  public DnsMessage query(DnsName qname, int qtype) throws IOException {
    IOException lastException = null;
    DnsMessage lastResponse = null;
    for (InetSocketAddress server : servers) {
      try {
        DnsMessage response = query(server, qname, qtype, true);
        int rcode = response.rcode();
        if (!dnssec && (rcode == DnsMessage.RCODE_FORMERR || rcode == DnsMessage.RCODE_NOTIMP)) {
          // server does not support EDNS
          response = query(server, qname, qtype, false);
          rcode = response.rcode();
        }

        if (rcode == DnsMessage.RCODE_SERVFAIL || rcode == DnsMessage.RCODE_REFUSED) {
          LOG.debug("DNS server {} returned {} for {}/{}", server,
              DnsMessage.rcodeText(rcode), qname, qtype);
          lastResponse = response;
          continue;
        }
        return response;
      } catch (IOException ex) {
        LOG.debug("DNS query {}/{} to {} failed: {}", qname, qtype, server, ex.getMessage());
        lastException = ex;
      }
    }

    if (lastResponse != null) {
      return lastResponse;
    }
    throw lastException;
  }

  private DnsMessage query(InetSocketAddress server, DnsName qname, int qtype, boolean edns)
      throws IOException {
    int id = RANDOM.nextInt(0x10000);
    byte[] query = DnsMessage.buildQuery(id, qname, qtype, edns, dnssec && edns);
    long deadline = System.currentTimeMillis() + timeoutMs;

    DnsMessage response = queryUdp(server, query, id, qname, qtype, deadline);
    if (response.flag(DnsMessage.FLAG_TC)) {
      response = queryTcp(server, query, id, qname, qtype, deadline);
    }
    return response;
  }

  private static DnsMessage queryUdp(InetSocketAddress server, byte[] query, int id,
                                     DnsName qname, int qtype, long deadline)
      throws IOException {
    try (DatagramSocket socket = new DatagramSocket()) {
      socket.connect(server);
      socket.send(new DatagramPacket(query, query.length));

      byte[] buf = new byte[MAX_MESSAGE_SIZE];
      while (true) {
        int remaining = (int) (deadline - System.currentTimeMillis());
        if (remaining <= 0) {
          throw new SocketTimeoutException("DNS query to " + server + " timed out");
        }
        socket.setSoTimeout(remaining);

        DatagramPacket packet = new DatagramPacket(buf, buf.length);
        socket.receive(packet);
        byte[] data = new byte[packet.getLength()];
        System.arraycopy(buf, 0, data, 0, data.length);

        DnsMessage response;
        try {
          response = DnsMessage.parse(data);
        } catch (DnsException ex) {
          LOG.debug("ignored malformed DNS response from {}: {}", server, ex.getMessage());
          continue;
        }

        if (matches(response, id, qname, qtype)) {
          return response;
        }
        LOG.debug("ignored non-matching DNS response from {}", server);
      }
    }
  }

  private static DnsMessage queryTcp(InetSocketAddress server, byte[] query, int id,
                                     DnsName qname, int qtype, long deadline)
      throws IOException {
    int remaining = (int) (deadline - System.currentTimeMillis());
    if (remaining <= 0) {
      throw new SocketTimeoutException("DNS query to " + server + " timed out");
    }

    try (Socket socket = new Socket()) {
      socket.connect(server, remaining);
      socket.setSoTimeout(remaining);

      OutputStream out = socket.getOutputStream();
      byte[] framed = new byte[2 + query.length];
      framed[0] = (byte) (query.length >>> 8);
      framed[1] = (byte) query.length;
      System.arraycopy(query, 0, framed, 2, query.length);
      out.write(framed);
      out.flush();

      DataInputStream in = new DataInputStream(socket.getInputStream());
      int len = in.readUnsignedShort();
      byte[] data = new byte[len];
      in.readFully(data);

      DnsMessage response = DnsMessage.parse(data);
      if (!matches(response, id, qname, qtype)) {
        throw new DnsException("non-matching DNS response over TCP from " + server);
      }
      return response;
    }
  }

  private static boolean matches(DnsMessage response, int id, DnsName qname, int qtype) {
    if (response.id() != id || !response.flag(DnsMessage.FLAG_QR)) {
      return false;
    }

    if (response.qname() == null) {
      // Some servers omit the question in error responses.
      int rcode = response.rcode();
      return rcode != DnsMessage.RCODE_NOERROR && rcode != DnsMessage.RCODE_NXDOMAIN;
    }

    return qname.equals(response.qname()) && response.qtype() == qtype
        && response.qclass() == DnsRecord.CLASS_IN;
  }

}
